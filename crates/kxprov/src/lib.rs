//! CLI defaults re-exported for integration tests (see `kxprov-api` path agreement test).

pub mod cli_defaults {
    pub use kxprov_api::{DAEMON_SOCKET, DATA_DIR, TOKENS_JSON};

    pub fn daemon_socket() -> &'static str {
        DAEMON_SOCKET
    }

    pub fn tokens_json() -> &'static str {
        TOKENS_JSON
    }

    pub fn sim_mark_data_dir() -> &'static str {
        DATA_DIR
    }
}
