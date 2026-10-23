//! `kxprovd`: single serial owner, one-worker queue, backups, journal, gates (A3/v2.3).

pub mod alert;
pub mod api;
pub mod apply;
pub mod approval;
pub mod backup;
pub mod config;
pub mod dbh;
pub mod gates;
pub mod goliath;
pub mod journal;
pub mod lock;
pub mod locked;
pub mod peer;
pub mod plan_store;
pub mod queue;
pub mod time;
pub mod tokens;
pub mod transport;
pub mod worker;

use api::ApiState;
use approval::ApprovalBook;
use backup::BackupStore;
use config::{Config, TransportKind};
use gates::GateState;
use goliath::GoliathQueue;
use journal::Journal;
use locked::LockedStore;
use plan_store::PlanStore;
use std::sync::Arc;
use tokens::TokenStore;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, RwLock};

pub struct Daemon {
    _process_lock: lock::ProcessLock,
    _thread: std::thread::JoinHandle<()>,
}

impl Daemon {
    pub fn start(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let process_lock = lock::ProcessLock::acquire(&config.data_dir)?;
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::create_dir_all(config.data_dir.join("plans"))?;
        std::fs::create_dir_all(config.data_dir.join("backups"))?;

        let journal = Journal::new(&config.data_dir);
        journal.replay(config.data_dir.join("backups").as_path())?;

        let plans = PlanStore::new(config.data_dir.join("plans"))?;
        let backups = BackupStore::new(config.data_dir.join("backups"))?;
        let goliath = GoliathQueue::new(config.goliath_target.clone())?;
        let approvals = ApprovalBook::new(&config.data_dir);
        let locked = LockedStore::new(&config.data_dir);

        let (job_tx, job_rx) = mpsc::channel(32);
        let queue = Arc::new(queue::JobQueue::new(job_tx));
        let gates = Arc::new(RwLock::new(GateState {
            config: config.gates,
        }));

        let transport_label = match config.transport {
            TransportKind::Sim => "sim".into(),
            TransportKind::Serial => "serial".into(),
        };

        let worker_ctx = Arc::new(worker::WorkerCtx {
            config: config.clone(),
            plans: PlanStore::new(config.data_dir.join("plans"))?,
            backups: BackupStore::new(config.data_dir.join("backups"))?,
            journal: Journal::new(&config.data_dir),
            goliath: goliath.clone(),
            locked: LockedStore::new(&config.data_dir),
        });

        let q = Arc::clone(&queue);
        let api_state = Arc::new(ApiState {
            profile: config.profile,
            transport_label,
            gates,
            peer_policy: config.peer_policy.clone(),
            tokens: TokenStore::with_test_defaults(),
            queue,
            backups,
            plans,
            approvals,
            locked,
            goliath,
            approval_url_base: config.approval_url_base.clone(),
        });

        let socket_path = config.socket_path.clone();
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let listener = match UnixListener::bind(&socket_path) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("bind {socket_path:?}: {e}");
                        return;
                    }
                };
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &socket_path,
                        std::fs::Permissions::from_mode(0o660),
                    );
                }
                let ((), serve_res) = tokio::join!(
                    worker::run_worker(job_rx, worker_ctx, q),
                    api::serve(listener, api_state),
                );
                let _ = serve_res;
            });
        });

        Ok(Self {
            _process_lock: process_lock,
            _thread: thread,
        })
    }

    pub fn sim_for_tests(
        data_dir: impl AsRef<std::path::Path>,
        peer_uid: u32,
    ) -> (Self, std::path::PathBuf) {
        let data_dir = data_dir.as_ref().to_path_buf();
        let socket = data_dir.join("kxprovd.sock");
        let mut cfg = Config::sim_test(data_dir, socket.clone(), peer_uid);
        cfg.gates.live_writes_approved = true;
        let daemon = Self::start(cfg).expect("daemon starts");
        (daemon, socket)
    }
}
