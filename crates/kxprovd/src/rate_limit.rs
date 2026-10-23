//! Per-token job rate limits (design v2.12): queue depth and starts per minute.

use std::collections::VecDeque;

pub use kxprov_api::{
    TOKEN_JOBS_PER_MINUTE as JOBS_PER_MINUTE, TOKEN_QUEUE_DEPTH_MAX as QUEUE_DEPTH_MAX,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitError {
    QueueDepth,
    JobsPerMinute,
}

#[derive(Default)]
pub struct TokenRateState {
    pub active: u32,
    pub start_times_ms: VecDeque<u64>,
}

impl TokenRateState {
    /// Reserve one job slot before enqueue; rolls back with [`Self::release`] if send fails.
    pub fn try_reserve(&mut self, now_ms: u64) -> Result<(), RateLimitError> {
        if self.active >= QUEUE_DEPTH_MAX {
            return Err(RateLimitError::QueueDepth);
        }
        let minute_ago = now_ms.saturating_sub(60_000);
        while self.start_times_ms.front().is_some_and(|t| *t < minute_ago) {
            self.start_times_ms.pop_front();
        }
        let starts = u32::try_from(self.start_times_ms.len()).unwrap_or(u32::MAX);
        if starts >= JOBS_PER_MINUTE {
            return Err(RateLimitError::JobsPerMinute);
        }
        self.active += 1;
        self.start_times_ms.push_back(now_ms);
        Ok(())
    }

    /// Job finished (or worker released token): free active slot only.
    pub fn complete(&mut self) {
        self.active = self.active.saturating_sub(1);
    }

    /// Undo [`Self::try_reserve`] when the job never entered the queue.
    pub fn rollback_reserve(&mut self) {
        self.active = self.active.saturating_sub(1);
        let _ = self.start_times_ms.pop_back();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn queue_depth_cap() {
        let mut st = TokenRateState::default();
        let base = 1_000_000_u64;
        for i in 0..QUEUE_DEPTH_MAX {
            st.try_reserve(base + u64::from(i)).expect("under cap");
        }
        assert_eq!(st.try_reserve(base + 100), Err(RateLimitError::QueueDepth));
    }

    #[test]
    fn jobs_per_minute_cap() {
        let mut st = TokenRateState::default();
        let base = 2_000_000_u64;
        for i in 0..JOBS_PER_MINUTE {
            st.try_reserve(base + u64::from(i)).expect("under cap");
            st.complete();
        }
        assert_eq!(
            st.try_reserve(base + JOBS_PER_MINUTE as u64),
            Err(RateLimitError::JobsPerMinute)
        );
    }

    #[test]
    fn rollback_reserve_after_failed_enqueue() {
        let mut st = TokenRateState::default();
        st.try_reserve(100).unwrap();
        assert_eq!(st.active, 1);
        st.rollback_reserve();
        assert_eq!(st.active, 0);
        st.try_reserve(101).unwrap();
    }
}
