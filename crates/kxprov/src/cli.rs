//! Clap schema shared by the binary and [`crate::cli_defaults`].

use clap::{Parser, Subcommand, ValueEnum};
use kxprov_api::{OperationalMode, Profile, DAEMON_SOCKET, DATA_DIR, TOKENS_JSON};
use kxtd1232::FieldKind;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "kxprov",
    version,
    about = "kx-provision CLI (A1: simulator only)"
)]
pub struct Cli {
    /// Transport. Only the in-process simulator exists in Phase A.
    #[arg(long, value_enum, default_value_t = TransportKind::Sim)]
    pub transport: TransportKind,
    /// Daemon Unix socket (admin commands only).
    #[arg(long, default_value = DAEMON_SOCKET)]
    pub socket: PathBuf,
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum TransportKind {
    Sim,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the CLI version and the PBX version probe.
    Version,
    /// Read typed fields.
    Read {
        /// cid_name, cid_number or ext_name
        kind: FieldKind,
        #[arg(long, default_value_t = 0)]
        first: u16,
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..))]
        count: u16,
    },
    /// Dry-run a typed field edit (no write is ever sent).
    Plan {
        kind: FieldKind,
        index: u16,
        value: String,
    },
    /// Clear persisted LOCKED state (root admin, after verified backup).
    Unlock {
        #[arg(long)]
        job: String,
        #[arg(long)]
        reason: String,
    },
    /// Operational mode and profile (v2.7 F1, root socket only).
    Mode {
        #[command(subcommand)]
        cmd: ModeCommand,
    },
    /// Record simulator test pass for this build hash (v2.7 F1).
    SimMark {
        #[command(subcommand)]
        cmd: SimMarkCommand,
    },
    /// Daemon bearer token admin (root; tokens file 0600).
    Token {
        #[command(subcommand)]
        cmd: TokenCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Replace a token secret (prints new bearer once).
    Rotate {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = TOKENS_JSON)]
        tokens_path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum ModeCommand {
    Set {
        #[arg(long, value_enum)]
        mode: OperationalModeCli,
        #[arg(long, value_enum)]
        profile: ProfileCli,
    },
}

#[derive(Subcommand, Debug)]
pub enum SimMarkCommand {
    /// Run simulator crate tests and write sim-mark.json on success.
    Write {
        #[arg(long, default_value = DATA_DIR)]
        data_dir: PathBuf,
    },
    /// Show whether the current build hash is marked.
    Status {
        #[arg(long, default_value = DATA_DIR)]
        data_dir: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OperationalModeCli {
    Testing,
    Production,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProfileCli {
    Sim,
    Test,
    Prod,
}

impl From<OperationalModeCli> for OperationalMode {
    fn from(v: OperationalModeCli) -> Self {
        match v {
            OperationalModeCli::Testing => OperationalMode::Testing,
            OperationalModeCli::Production => OperationalMode::Production,
        }
    }
}

impl From<ProfileCli> for Profile {
    fn from(v: ProfileCli) -> Self {
        match v {
            ProfileCli::Sim => Profile::Sim,
            ProfileCli::Test => Profile::Test,
            ProfileCli::Prod => Profile::Prod,
        }
    }
}
