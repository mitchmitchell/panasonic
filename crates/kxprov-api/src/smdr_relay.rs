//! Bounded relay from a live-call broadcast to one subscriber (S6 design §2, §4).

use crate::{SmdrAlert, SmdrCallView, SmdrStreamEvent};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

/// Events buffered per subscriber before the relay stops reading the broadcast.
pub const SMDR_RELAY_BUFFER: usize = 16;

/// Spawns a task that sends `replay`, then live calls, lag notices and heartbeats.
///
/// The publisher never waits on a subscriber: a slow consumer fills this relay's small
/// buffer, the relay stops draining its broadcast receiver, and the broadcast reports the
/// overflow as [`SmdrStreamEvent::Lagged`]. Calls at or below the last id sent are skipped,
/// so subscribing before reading the replay never shows a call twice. The task ends when the
/// receiver is dropped or the broadcast closes.
pub fn spawn_smdr_relay(
    replay: Vec<SmdrCallView>,
    replay_truncated: u64,
    live: broadcast::Receiver<SmdrCallView>,
    heartbeat: Duration,
) -> mpsc::Receiver<SmdrStreamEvent> {
    spawn_smdr_relay_with_alerts(replay, replay_truncated, live, None, heartbeat)
}

/// Same as [`spawn_smdr_relay`], also forwarding S7 alert edges as [`SmdrStreamEvent::Alert`].
///
/// A subscriber that falls behind on alerts gets no lag event for them: the active set is
/// always readable from `smdr_status`, so a missed edge is recovered by one status call.
pub fn spawn_smdr_relay_with_alerts(
    replay: Vec<SmdrCallView>,
    replay_truncated: u64,
    mut live: broadcast::Receiver<SmdrCallView>,
    mut alerts: Option<broadcast::Receiver<SmdrAlert>>,
    heartbeat: Duration,
) -> mpsc::Receiver<SmdrStreamEvent> {
    let (tx, rx) = mpsc::channel(SMDR_RELAY_BUFFER);
    tokio::spawn(async move {
        let mut last_id = i64::MIN;
        if replay_truncated > 0
            && tx
                .send(SmdrStreamEvent::Lagged {
                    skipped: replay_truncated,
                })
                .await
                .is_err()
        {
            return;
        }
        for call in replay {
            last_id = last_id.max(call.id);
            if tx.send(SmdrStreamEvent::Call { call }).await.is_err() {
                return;
            }
        }
        let mut beat = tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);
        loop {
            let event = tokio::select! {
                got = live.recv() => match got {
                    Ok(call) if call.id <= last_id => continue,
                    Ok(call) => {
                        last_id = call.id;
                        SmdrStreamEvent::Call { call }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        SmdrStreamEvent::Lagged { skipped }
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                got = next_alert(&mut alerts) => match got {
                    Ok(alert) => SmdrStreamEvent::Alert { alert },
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::debug!(missed, "alert edges missed; smdr_status has the active set");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        alerts = None;
                        continue;
                    }
                },
                _tick = beat.tick() => SmdrStreamEvent::Heartbeat,
            };
            if tx.send(event).await.is_err() {
                return;
            }
        }
    });
    rx
}

async fn next_alert(
    alerts: &mut Option<broadcast::Receiver<SmdrAlert>>,
) -> Result<SmdrAlert, broadcast::error::RecvError> {
    match alerts {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test setup failures should abort the test"
    )]
    use super::*;
    use crate::CallDirection;

    fn call(id: i64) -> SmdrCallView {
        SmdrCallView {
            id,
            rx_ts_utc: String::new(),
            pbx_local: String::new(),
            ext: String::new(),
            co: String::new(),
            direction: CallDirection::Incoming,
            number: String::new(),
            cid_text: None,
            ring_s: None,
            duration_s: None,
            acc: None,
            raw: None,
        }
    }

    fn id(e: &SmdrStreamEvent) -> Option<i64> {
        match e {
            SmdrStreamEvent::Call { call } => Some(call.id),
            _not_a_call => None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn replay_then_live_without_duplicates_then_heartbeat() {
        let (tx, live) = broadcast::channel(crate::SMDR_BUS_CAPACITY);
        tx.send(call(2)).unwrap();
        let mut rx = spawn_smdr_relay(vec![call(1), call(2)], 0, live, Duration::from_secs(15));
        for want in [1, 2] {
            assert_eq!(id(&rx.recv().await.unwrap()), Some(want));
        }
        tx.send(call(3)).unwrap();
        assert_eq!(id(&rx.recv().await.unwrap()), Some(3));
        assert_eq!(rx.recv().await.unwrap(), SmdrStreamEvent::Heartbeat);
    }

    #[tokio::test]
    async fn a_slow_subscriber_lags_and_the_publisher_never_waits() {
        let (tx, live) = broadcast::channel(crate::SMDR_BUS_CAPACITY);
        let mut rx = spawn_smdr_relay(Vec::new(), 0, live, Duration::from_secs(3600));
        for i in 0..2_000 {
            assert!(
                tx.send(call(i)).is_ok(),
                "send is synchronous and never blocks"
            );
        }
        let mut lagged = 0;
        let mut calls = 0;
        while calls + lagged < 2_000 {
            match rx.recv().await.unwrap() {
                SmdrStreamEvent::Lagged { skipped } => lagged += skipped,
                SmdrStreamEvent::Call { .. } => calls += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(lagged > 0, "a backlog past capacity is reported as lag");
    }

    #[tokio::test]
    async fn a_truncated_replay_starts_with_lagged() {
        let (_tx, live) = broadcast::channel(crate::SMDR_BUS_CAPACITY);
        let mut rx = spawn_smdr_relay(vec![call(9)], 40, live, Duration::from_secs(3600));
        assert_eq!(
            rx.recv().await.unwrap(),
            SmdrStreamEvent::Lagged { skipped: 40 }
        );
        assert_eq!(id(&rx.recv().await.unwrap()), Some(9));
    }

    #[tokio::test(start_paused = true)]
    async fn alert_edges_are_forwarded_as_alert_events() {
        let (_calls, live) = broadcast::channel(crate::SMDR_BUS_CAPACITY);
        let (alert_tx, alerts) = broadcast::channel(4);
        let mut rx = spawn_smdr_relay_with_alerts(
            Vec::new(),
            0,
            live,
            Some(alerts),
            Duration::from_secs(3600),
        );
        let alert = SmdrAlert {
            kind: crate::SmdrAlertKind::LineSilence,
            state: crate::SmdrAlertState::Raised {
                since: "2026-11-02T18:00:00.000Z".into(),
            },
        };
        alert_tx.send(alert.clone()).unwrap();
        assert_eq!(rx.recv().await.unwrap(), SmdrStreamEvent::Alert { alert });
    }

    #[tokio::test]
    async fn the_relay_stops_when_the_subscriber_goes_away() {
        let (tx, live) = broadcast::channel(crate::SMDR_BUS_CAPACITY);
        let rx = spawn_smdr_relay(Vec::new(), 0, live, Duration::from_secs(3600));
        drop(rx);
        tx.send(call(1)).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while tx.receiver_count() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
