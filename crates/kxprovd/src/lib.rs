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
pub mod epoch_store;
pub mod gates;
pub mod goliath;
pub mod job_principal;
pub mod journal;
pub mod lock;
pub mod locked;
pub mod mode;
pub mod peer;
pub mod plan_live;
pub mod plan_store;
pub mod port;
pub mod queue;
pub mod rate_limit;
pub mod sim_mark;
pub mod smdr_reader;
pub mod smdr_store;
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

#[cfg(unix)]
fn set_daemon_socket_permissions(
    path: &std::path::Path,
    group_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if group_name.is_empty() {
        return Ok(());
    }
    let gid = nix::unistd::Group::from_name(group_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("daemon socket group {group_name:?} not found"),
            )
        })?
        .gid;
    let owner = if nix::unistd::geteuid().is_root() {
        nix::unistd::Uid::from_raw(0)
    } else {
        nix::unistd::geteuid()
    };
    nix::unistd::chown(path, Some(owner), Some(gid))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_daemon_socket_permissions(
    _path: &std::path::Path,
    _group_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Ok(())
}

/// Bind the daemon socket and apply mode/group before returning (fail-fast for `Daemon::start`).
#[cfg(unix)]
fn prepare_daemon_unix_socket(
    socket_path: &std::path::Path,
    group_name: &str,
) -> Result<std::os::unix::net::UnixListener, Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::net::UnixListener as StdUnixListener;
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let std_listener = StdUnixListener::bind(socket_path)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    if let Err(e) = set_daemon_socket_permissions(socket_path, group_name) {
        let _ = std::fs::remove_file(socket_path);
        return Err(e);
    }
    Ok(std_listener)
}

#[cfg(unix)]
fn tokio_listener_from_prepared(
    std_listener: std::os::unix::net::UnixListener,
) -> Result<UnixListener, Box<dyn std::error::Error + Send + Sync>> {
    UnixListener::from_std(std_listener)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

const DAEMON_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(unix)]
fn spawn_daemon_thread(
    prepared_socket: std::os::unix::net::UnixListener,
    job_rx: mpsc::Receiver<queue::JobRequest>,
    worker_ctx: Arc<worker::WorkerCtx>,
    q: Arc<queue::JobQueue>,
    api_state: Arc<ApiState>,
) -> Result<std::thread::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = match tokio_listener_from_prepared(prepared_socket) {
                Ok(l) => l,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("tokio listener: {e}")));
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                return;
            }
            let tokens_worker = api_state.tokens.clone();
            let ((), serve_res) = tokio::join!(
                worker::run_worker(job_rx, worker_ctx, q, tokens_worker),
                api::serve(listener, api_state),
            );
            let _ = serve_res;
        });
    });
    match ready_rx.recv_timeout(DAEMON_STARTUP_TIMEOUT) {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(msg)) => Err(msg.into()),
        Err(mpsc::RecvTimeoutError::Timeout) => Err("daemon worker did not become ready".into()),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("daemon worker exited before becoming ready".into())
        }
    }
}

pub struct Daemon {
    _process_lock: lock::ProcessLock,
    _thread: std::thread::JoinHandle<()>,
}

impl Daemon {
    fn load_tokens(
        config: &Config,
    ) -> Result<TokenStore, Box<dyn std::error::Error + Send + Sync>> {
        let map_err = |e: tokens::TokenError| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                e.to_string(),
            )) as Box<dyn std::error::Error + Send + Sync>
        };
        #[cfg(feature = "test-util")]
        {
            use kxprov_api::Profile;
            if config.profile == Profile::Sim && config.transport == TransportKind::Sim {
                return TokenStore::load_insecure(config.tokens_path.clone()).map_err(map_err);
            }
        }
        TokenStore::load(config.tokens_path.clone()).map_err(map_err)
    }

    pub fn start(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;
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
        let transition = transition::TransitionBlockStore::new(&config.data_dir);
        let mode = mode::ModeStore::new_with_epoch_root(
            &config.data_dir,
            &config.provision_root,
            config.profile,
        );
        let _ = sim_mark::SimMarkStore::new(&config.provision_root).clear_if_stale();
        let profile = Arc::new(RwLock::new(mode.load_profile()));

        let (job_tx, job_rx) = mpsc::channel(32);
        let queue = Arc::new(queue::JobQueue::new(job_tx));

        let tokens = Self::load_tokens(&config)?;
        tokens.attach_job_queue(Arc::downgrade(&queue));
        let gates = Arc::new(RwLock::new(GateState {
            config: config.gates,
        }));

        let transport_label = match config.transport {
            TransportKind::Sim => "sim".into(),
            TransportKind::Serial => "serial".into(),
        };

        let port = transport::device_arbiter(&config);
        let worker_ctx = Arc::new(worker::WorkerCtx {
            config: config.clone(),
            port: Arc::clone(&port),
            profile: Arc::clone(&profile),
            plans: PlanStore::new(config.data_dir.join("plans"))?,
            backups: BackupStore::new(config.data_dir.join("backups"))?,
            journal: Journal::new(&config.data_dir),
            goliath: goliath.clone(),
            locked: LockedStore::new(&config.data_dir),
            gates: Arc::clone(&gates),
            transition: transition::TransitionBlockStore::new(&config.data_dir),
            approvals: approvals.clone(),
        });

        let q = Arc::clone(&queue);
        let api_state = Arc::new(ApiState {
            config: config.clone(),
            port,
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

        let prepared_socket =
            prepare_daemon_unix_socket(&config.socket_path, &config.daemon_socket_group)?;
        let socket_path = config.socket_path.clone();
        let thread = match spawn_daemon_thread(prepared_socket, job_rx, worker_ctx, q, api_state) {
            Ok(t) => t,
            Err(e) => {
                let _ = std::fs::remove_file(&socket_path);
                return Err(e);
            }
        };

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
    pub fn sim_for_tests_serial_profile(
        data_dir: impl AsRef<std::path::Path>,
        peer_uid: u32,
        profile: kxprov_api::Profile,
    ) -> (Self, std::path::PathBuf) {
        let data_dir = data_dir.as_ref().to_path_buf();
        test_util::write_integration_tokens(&data_dir.join("tokens.json"));
        let socket = data_dir.join("kxprovd.sock");
        let mut cfg = Config::sim_test(data_dir, socket.clone(), peer_uid);
        cfg.profile = profile;
        cfg.data_dir = config::profile_data_dir(&cfg.provision_root, profile);
        cfg.goliath_target = cfg.data_dir.join("goliath");
        cfg.transport = TransportKind::Serial;
        cfg.sim_pbx = None;
        let daemon = Self::start_test(cfg).expect("daemon starts");
        (daemon, socket)
    }

    #[cfg(feature = "test-util")]
    pub fn sim_for_tests_as_gateway_profile(
        data_dir: impl AsRef<std::path::Path>,
        gateway_uid: u32,
        profile: kxprov_api::Profile,
    ) -> (Self, std::path::PathBuf) {
        let data_dir = data_dir.as_ref().to_path_buf();
        test_util::write_integration_tokens(&data_dir.join("tokens.json"));
        let socket = data_dir.join("kxprovd.sock");
        let mut cfg = Config::sim_test_gateway_caller(data_dir, socket.clone(), gateway_uid);
        cfg.profile = profile;
        cfg.data_dir = config::profile_data_dir(&cfg.provision_root, profile);
        cfg.goliath_target = cfg.data_dir.join("goliath");
        if profile == Profile::Prod {
            cfg.gates.live_writes_approved = true;
        }
        let daemon = Self::start_test(cfg).expect("daemon starts");
        (daemon, socket)
    }

    #[cfg(feature = "test-util")]
    pub fn sim_for_tests_profile(
        data_dir: impl AsRef<std::path::Path>,
        peer_uid: u32,
        profile: kxprov_api::Profile,
    ) -> (Self, std::path::PathBuf) {
        Self::sim_for_tests_profile_peers(
            data_dir,
            peer_uid,
            profile,
            peer_uid.wrapping_add(1),
            peer_uid,
        )
    }

    /// Same as [`sim_for_tests_profile`], but `peer_uid` is the connecting UID while admin/gateway differ.
    #[cfg(feature = "test-util")]
    pub fn sim_for_tests_profile_peers(
        data_dir: impl AsRef<std::path::Path>,
        peer_uid: u32,
        profile: kxprov_api::Profile,
        gateway_uid: u32,
        admin_uid: u32,
    ) -> (Self, std::path::PathBuf) {
        let data_dir = data_dir.as_ref().to_path_buf();
        test_util::write_integration_tokens(&data_dir.join("tokens.json"));
        let socket = data_dir.join("kxprovd.sock");
        let mut cfg = Config::sim_test(data_dir, socket.clone(), peer_uid);
        cfg.profile = profile;
        cfg.data_dir = config::profile_data_dir(&cfg.provision_root, profile);
        cfg.goliath_target = cfg.data_dir.join("goliath");
        cfg.gateway_uid = gateway_uid;
        cfg.admin_uid = admin_uid;
        cfg.peer_policy = peer::PeerPolicy::new(gateway_uid, admin_uid);
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
        journal.replay(config.data_dir.join("backups").as_path())?;

        let plans = PlanStore::new(config.data_dir.join("plans"))?;
        let backups = BackupStore::new(config.data_dir.join("backups"))?;
        let goliath = GoliathQueue::new(config.goliath_target.clone())?;
        let approvals = ApprovalBook::new(&config.data_dir);
        let locked = LockedStore::new(&config.data_dir);
        let transition = transition::TransitionBlockStore::new(&config.data_dir);
        let mode = mode::ModeStore::new_with_epoch_root(
            &config.data_dir,
            &config.provision_root,
            config.profile,
        );
        let _ = sim_mark::SimMarkStore::new(&config.provision_root).clear_if_stale();
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

        let port = transport::device_arbiter(&config);
        let worker_ctx = Arc::new(worker::WorkerCtx {
            config: config.clone(),
            port: Arc::clone(&port),
            profile: Arc::clone(&profile),
            plans: PlanStore::new(config.data_dir.join("plans"))?,
            backups: BackupStore::new(config.data_dir.join("backups"))?,
            journal: Journal::new(&config.data_dir),
            goliath: goliath.clone(),
            locked: LockedStore::new(&config.data_dir),
            gates: Arc::clone(&gates),
            transition: transition::TransitionBlockStore::new(&config.data_dir),
            approvals: approvals.clone(),
        });

        let q = Arc::clone(&queue);
        let api_state = Arc::new(ApiState {
            config: config.clone(),
            port,
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

        let prepared_socket =
            prepare_daemon_unix_socket(&config.socket_path, &config.daemon_socket_group)?;
        let socket_path = config.socket_path.clone();
        let thread = match spawn_daemon_thread(prepared_socket, job_rx, worker_ctx, q, api_state) {
            Ok(t) => t,
            Err(e) => {
                let _ = std::fs::remove_file(&socket_path);
                return Err(e);
            }
        };

        Ok(Self {
            _process_lock: process_lock,
            _thread: thread,
        })
    }
}
