//! `kxprov`: kx-provision CLI. A1 scope: simulator only, read-only and dry-run.
//!
//! Exit codes: 0 success; 1 runtime error, including a refused plan (for example a table
//! outside the write allow-list) and protocol, frame or login failures; 2 usage error
//! (bad arguments, out-of-range records, invalid field values). Errors print one line,
//! `kxprov: error: ...`, with no backtrace.

use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use kxprov_api::mode_sign_message;
use kxprov_api::{OperationalMode, SetModeParams};
use kxtd1232::error::NotAllowed;
use kxtd1232::{build_plan, field_patch, Client, Error, FieldKind, Granularity};
use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "kxprov",
    version,
    about = "kx-provision CLI (A1: simulator only)"
)]
struct Cli {
    /// Transport. Only the in-process simulator exists in Phase A.
    #[arg(long, value_enum, default_value_t = TransportKind::Sim)]
    transport: TransportKind,
    /// Daemon Unix socket (admin commands only).
    #[arg(long, default_value = "/run/kx-provision/kxprovd.sock")]
    socket: std::path::PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum TransportKind {
    Sim,
}

#[derive(Subcommand, Debug)]
enum Command {
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
    /// Operational mode (v2.6 F1, root socket only).
    Mode {
        #[command(subcommand)]
        cmd: ModeCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ModeCommand {
    /// Install a signed mode.json via the daemon.
    Set {
        #[arg(long, value_enum)]
        mode: OperationalModeCli,
        #[arg(long)]
        counter: u64,
        /// 32-byte ed25519 seed file (ed25519-sk material).
        #[arg(long)]
        signing_key: std::path::PathBuf,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OperationalModeCli {
    Testing,
    Production,
}

impl From<OperationalModeCli> for OperationalMode {
    fn from(v: OperationalModeCli) -> Self {
        match v {
            OperationalModeCli::Testing => OperationalMode::Testing,
            OperationalModeCli::Production => OperationalMode::Production,
        }
    }
}

/// CLI failure, split by exit code.
#[derive(Debug)]
enum CliError {
    Usage(String),
    Runtime(Error),
}

impl CliError {
    fn code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Runtime(_) => 1,
        }
    }
}

impl From<Error> for CliError {
    fn from(e: Error) -> Self {
        match e {
            Error::Field(_) | Error::NotAllowed(NotAllowed::RecordOutOfRange { .. }) => {
                Self::Usage(e.to_string())
            }
            e => Self::Runtime(e),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(s) => f.write_str(s),
            Self::Runtime(e) => write!(f, "{e}"),
        }
    }
}

fn check_ranges(cmd: &Command) -> Result<(), CliError> {
    match *cmd {
        Command::Read { kind, first, count } => {
            let limit = kind.records();
            if u32::from(first) + u32::from(count) > u32::from(limit) {
                return Err(CliError::Usage(format!(
                    "records {first}..{} out of range 0..{}",
                    u32::from(first) + u32::from(count) - 1,
                    limit - 1
                )));
            }
        }
        Command::Plan { kind, index, .. } if index >= kind.records() => {
            return Err(CliError::Usage(format!(
                "record {index} out of range 0..{}",
                kind.records() - 1
            )));
        }
        _ => {}
    }
    Ok(())
}

fn run(cli: &Cli) -> Result<(), CliError> {
    if matches!(cli.cmd, Command::Unlock { .. }) {
        return unlock_daemon(cli);
    }
    if matches!(cli.cmd, Command::Mode { .. }) {
        return mode_daemon(cli);
    }
    check_ranges(&cli.cmd)?;
    let TransportKind::Sim = cli.transport;
    let mut c = Client::new(SimTransport::new(SimPbx::default()));
    c.login(PLACEHOLDER_PASSWORD)?;
    let result = command(&mut c, &cli.cmd);
    // Always try to leave binary mode. A teardown failure is reported only when the
    // command itself succeeded, so the original error is never masked. Both sides are the
    // typed kxtd1232::Error; there is no catch-all.
    let teardown = c.end_binary();
    match (result, teardown) {
        (Err(e), _) => Err(e),
        (Ok(()), Err(e)) => Err(CliError::Runtime(e)),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn command(c: &mut Client<SimTransport>, cmd: &Command) -> Result<(), CliError> {
    match cmd {
        Command::Version => {
            println!("kxprov {}", env!("CARGO_PKG_VERSION"));
            println!("pbx {}", c.version()?);
        }
        Command::Read { kind, first, count } => {
            let size = kind.record_size();
            let raw = c.read_records(kind.table(), *first, *count)?;
            for (i, rec) in raw.chunks(size).enumerate() {
                let v = kind
                    .decode(rec)
                    .map_err(Error::Field)
                    .map_err(CliError::Runtime)?;
                println!("{}\t{v}", u32::from(*first) + i as u32);
            }
        }
        Command::Unlock { .. } => unreachable!("handled in unlock_daemon"),
        Command::Mode { .. } => unreachable!("handled in mode_daemon"),
        Command::Plan { kind, index, value } => {
            let patch = field_patch(*kind, *index, value)?;
            kxtd1232::tables::check_writable_table(kind.table()).map_err(Error::from)?;
            let base = c.read_table(kind.table())?;
            let plan = build_plan(kind.table(), &base, &[patch], Granularity::Chunk)?;
            let diff: Vec<String> = plan.diff().iter().map(|d| json_str(d)).collect();
            println!(
                "{{\"table\": {}, \"writes\": {}, \"diff\": [{}]}}",
                plan.table,
                plan.writes.len(),
                diff.join(", ")
            );
        }
    }
    Ok(())
}

fn mode_daemon(cli: &Cli) -> Result<(), CliError> {
    let Command::Mode { cmd } = &cli.cmd else {
        return Err(CliError::Usage("mode".into()));
    };
    let ModeCommand::Set {
        mode,
        counter,
        signing_key,
    } = cmd;
    let seed = std::fs::read(signing_key).map_err(|e| CliError::Usage(e.to_string()))?;
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| CliError::Usage("signing key must be 32 bytes".into()))?;
    let key = SigningKey::from_bytes(&seed);
    let op: OperationalMode = (*mode).into();
    let msg = mode_sign_message(op, *counter);
    let sig = key.sign(&msg);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Usage(e.to_string()))?;
    rt.block_on(async {
        let mut c = kxprov_api::ApiClient::connect(&cli.socket)
            .await
            .map_err(|e| CliError::Usage(e.to_string()))?;
        c.call(kxprov_api::RequestBody::SetMode {
            params: SetModeParams {
                mode: op,
                counter: *counter,
                signature: hex::encode(sig.to_bytes()),
            },
        })
        .await
        .map_err(|e| CliError::Usage(e.to_string()))?;
        Ok(())
    })
}

fn unlock_daemon(cli: &Cli) -> Result<(), CliError> {
    let Command::Unlock { job, reason } = &cli.cmd else {
        return Err(CliError::Usage("unlock".into()));
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Usage(e.to_string()))?;
    rt.block_on(async {
        let mut c = kxprov_api::ApiClient::connect(&cli.socket)
            .await
            .map_err(|e| CliError::Usage(e.to_string()))?;
        c.call(kxprov_api::RequestBody::Unlock {
            params: kxprov_api::UnlockParams {
                job_id: job.clone(),
                reason: reason.clone(),
            },
        })
        .await
        .map_err(|e| CliError::Usage(e.to_string()))?;
        Ok(())
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kxprov: error: {e}");
            ExitCode::from(e.code())
        }
    }
}
