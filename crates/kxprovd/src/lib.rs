//! `kxprovd`: single serial owner, one-worker queue, backups, journal, gates (A3/v2.3).

pub mod alert;
pub mod api;
pub mod apply;
pub mod approval;
pub mod atomic_write;
pub mod audit;
pub mod backup;
pub mod config;
pub mod dbh;
pub mod gates;
pub mod goliath;
pub mod journal;
pub mod lock;
pub mod locked;
pub mod mode;
pub mod peer;
pub mod plan_live;
pub mod plan_store;
pub mod queue;
pub mod rate_limit;
pub mod sim_mark;
#[cfg(feature = "test-util")]
pub mod test_util;
pub mod time;
pub mod tokens;
pub mod transition;
pub mod transport;
pub mod worker;

use api::ApiState;
use approval::ApprovalBook;
use backup::BackupStore;
use config::{Config, TransportKind};
use gates::GateState;
use goliath::GoliathQueue;
use journal::Journal;
#[cfg(feature = "test-util")]
use kxprov_api::Profile;
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

fn bind_unix_listener(
    socket_path: &std::path::Path,
) -> Result<UnixListener, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener as StdUnixListener;
        let std_listener = StdUnixListener::bind(socket_path)?;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
        std_listener.set_nonblocking(true)?;
        UnixListener::from_std(std_listener).map_err(|e| Box::new(e) as _)
    }
    #[cfg(not(unix))]
    {
        UnixListener::bind(socket_path).map_err(|e| Box::new(e) as _)
    }
}

impl Daemon {
    pub fn start(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;
        let process_lock = lock::ProcessLock::acquire(&config.data_dir)?;
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::create_dir_all(config.data_dir.join("plans"))?;
        std::fs::create_dir_all(config.data_dir.join("backups"))?;

        let journal = Journal::new(&config.data_dir);
        journal.replay(&config.data_dir)?;

        let plans = PlanStore::new(config.data_dir.join("plans"))?;
        let backups = BackupStore::new(config.data_dir.join("backups"))?;
        let goliath = GoliathQueue::new(config.goliath_target.clone())?;
        let approvals = ApprovalBook::new(&config.data_dir);
        let locked = LockedStore::new(&config.data_dir);
        let transition = transition::TransitionBlockStore::new(&config.data_dir);
        let mode = mode::ModeStore::new(&config.data_dir, config.profile);
        let _ = sim_mark::SimMarkStore::new(&config.data_dir).clear_if_stale();
        let profile = Arc::new(RwLock::new(mode.load_profile()));

        let (job_tx, job_rx) = mpsc::channel(32);
        let queue = Arc::new(queue::JobQueue::new(job_tx));

        let tokens = TokenStore::load(config.tokens_path.clone()).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                e.to_string(),
            )) as Box<dyn std::error::Error + Send + Sync>
        })?;
        tokens.attach_job_queue(Arc::downgrade(&queue));
        let gates = Arc::new(RwLock::new(GateState {
            config: config.gates,
        }));

        let transport_label = match config.transport {
            TransportKind::Sim => "sim".into(),
            TransportKind::Serial => "serial".into(),
        };

        let worker_ctx = Arc::new(worker::WorkerCtx {
            config: config.clone(),
            profile: Arc::clone(&profile),
            plans: PlanStore::new(config.data_dir.join("plans"))?,
            backups: BackupStore::new(config.data_dir.join("backups"))?,
            journal: Journal::new(&config.data_dir),
            goliath: goliath.clone(),
            locked: LockedStore::new(&config.data_dir),
        });

        let q = Arc::clone(&queue);
        let api_state = Arc::new(ApiState {
            config: config.clone(),
            profile: Arc::clone(&profile),
            transport_label,
            gates,
            peer_policy: config.peer_policy.clone(),
            tokens,
            queue,
            backups,
            plans,
            approvals,
            locked,
            goliath,
            mode,
            transition,
        });

        let listener = bind_unix_listener(&config.socket_path)?;

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let tokens_worker = api_state.tokens.clone();
                let ((), serve_res) = tokio::join!(
                    worker::run_worker(job_rx, worker_ctx, q, tokens_worker),
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

    #[cfg(feature = "test-util")]
    pub fn sim_for_tests(
        data_dir: impl AsRef<std::path::Path>,
        peer_uid: u32,
    ) -> (Self, std::path::PathBuf) {
        Self::sim_for_tests_profile(data_dir, peer_uid, Profile::Sim)
    }

    #[cfg(feature = "test-util")]
    pub fn sim_for_tests_profile(
        data_dir: impl AsRef<std::path::Path>,
        peer_uid: u32,
        profile: kxprov_api::Profile,
    ) -> (Self, std::path::PathBuf) {
        let data_dir = data_dir.as_ref().to_path_buf();
        test_util::write_integration_tokens(&data_dir.join("tokens.json"));
        let socket = data_dir.join("kxprovd.sock");
        let mut cfg = Config::sim_test(data_dir, socket.clone(), peer_uid);
        cfg.profile = profile;
        if profile == Profile::Prod {
            cfg.gates.live_writes_approved = true;
        }
        let daemon = Self::start_test(cfg).expect("daemon starts");
        (daemon, socket)
    }

    #[cfg(feature = "test-util")]
    fn start_test(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;
        let process_lock = lock::ProcessLock::acquire(&config.data_dir)?;
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::create_dir_all(config.data_dir.join("plans"))?;
        std::fs::create_dir_all(config.data_dir.join("backups"))?;

        let journal = Journal::new(&config.data_dir);
        journal.replay(&config.data_dir)?;

        let plans = PlanStore::new(config.data_dir.join("plans"))?;
        let backups = BackupStore::new(config.data_dir.join("backups"))?;
        let goliath = GoliathQueue::new(config.goliath_target.clone())?;
        let approvals = ApprovalBook::new(&config.data_dir);
        let locked = LockedStore::new(&config.data_dir);
        let transition = transition::TransitionBlockStore::new(&config.data_dir);
        let mode = mode::ModeStore::new(&config.data_dir, config.profile);
        let _ = sim_mark::SimMarkStore::new(&config.data_dir).clear_if_stale();
        let profile = Arc::new(RwLock::new(mode.load_profile()));

        let (job_tx, job_rx) = mpsc::channel(32);
        let queue = Arc::new(queue::JobQueue::new(job_tx));

        let tokens = TokenStore::load_insecure(config.tokens_path.clone())?;
        tokens.attach_job_queue(Arc::downgrade(&queue));
        let gates = Arc::new(RwLock::new(GateState {
            config: config.gates,
        }));

        let transport_label = match config.transport {
            TransportKind::Sim => "sim".into(),
            TransportKind::Serial => "serial".into(),
        };

        let worker_ctx = Arc::new(worker::WorkerCtx {
            config: config.clone(),
            profile: Arc::clone(&profile),
            plans: PlanStore::new(config.data_dir.join("plans"))?,
            backups: BackupStore::new(config.data_dir.join("backups"))?,
            journal: Journal::new(&config.data_dir),
            goliath: goliath.clone(),
            locked: LockedStore::new(&config.data_dir),
        });

        let q = Arc::clone(&queue);
        let api_state = Arc::new(ApiState {
            config: config.clone(),
            profile: Arc::clone(&profile),
            transport_label,
            gates,
            peer_policy: config.peer_policy.clone(),
            tokens,
            queue,
            backups,
            plans,
            approvals,
            locked,
            goliath,
            mode,
            transition,
        });

        let listener = bind_unix_listener(&config.socket_path)?;

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let tokens_worker = api_state.tokens.clone();
                let ((), serve_res) = tokio::join!(
                    worker::run_worker(job_rx, worker_ctx, q, tokens_worker),
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
}
