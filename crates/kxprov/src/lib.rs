//! Library surface for integration tests (path defaults derived from clap).

pub mod cli;

pub mod cli_defaults {
    use clap::Parser;
    use kxprov_api::{sim_passed_path, DATA_DIR};

    use crate::cli::{Cli, Command, SimMarkCommand, TokenCommand};

    pub fn daemon_socket() -> std::path::PathBuf {
        Cli::try_parse_from(["kxprov", "version"])
            .expect("probe parse")
            .socket
    }

    pub fn tokens_json() -> std::path::PathBuf {
        match Cli::try_parse_from(["kxprov", "token", "rotate", "--id", "_probe"])
            .expect("probe parse")
            .cmd
        {
            Command::Token {
                cmd: TokenCommand::Rotate { tokens_path, .. },
            } => tokens_path,
            _ => unreachable!("token rotate probe"),
        }
    }

    pub fn sim_mark_data_dir() -> std::path::PathBuf {
        match Cli::try_parse_from(["kxprov", "sim-mark", "status"])
            .expect("probe parse")
            .cmd
        {
            Command::SimMark {
                cmd: SimMarkCommand::Status { data_dir },
            } => data_dir,
            _ => unreachable!("sim-mark status probe"),
        }
    }

    pub fn sim_passed_file() -> std::path::PathBuf {
        sim_passed_path(std::path::Path::new(DATA_DIR))
    }
}
