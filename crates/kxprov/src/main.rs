//! `kxprov`: kx-provision CLI. A1 scope: simulator only, read-only and dry-run.
//!
//! Exit codes: 0 success; 1 runtime error, including a refused plan (for example a table
//! outside the write allow-list) and protocol, frame or login failures; 2 usage error
//! (bad arguments, out-of-range records, invalid field values). Errors print one line,
//! `kxprov: error: ...`, with no backtrace.

use clap::{Parser, Subcommand, ValueEnum};
use kxprov_api::{OperationalMode, Profile, SetModeParams};
use kxtd1232::error::NotAllowed;
use kxtd1232::{build_plan, field_patch, Client, Error, FieldKind, Granularity};
use kxtd1232_sim::{SimPbx, SimTransport, PLACEHOLDER_PASSWORD};
use std::path::PathBuf;
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
}

#[derive(Subcommand, Debug)]
enum ModeCommand {
    Set {
        #[arg(long, value_enum)]
        mode: OperationalModeCli,
        #[arg(long, value_enum)]
        profile: ProfileCli,
    },
}

#[derive(Subcommand, Debug)]
enum SimMarkCommand {
    /// Run simulator crate tests and write sim-mark.json on success.
    Write {
        #[arg(long, default_value = "/var/lib/kx-provision")]
        data_dir: PathBuf,
    },
    /// Show whether the current build hash is marked.
    Status {
        #[arg(long, default_value = "/var/lib/kx-provision")]
        data_dir: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OperationalModeCli {
    Testing,
    Production,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ProfileCli {
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
    if matches!(cli.cmd, Command::SimMark { .. }) {
        return sim_mark(cli);
    }
    check_ranges(&cli.cmd)?;
    let TransportKind::Sim = cli.transport;
    let mut c = Client::new(SimTransport::new(SimPbx::default()));
    c.login(PLACEHOLDER_PASSWORD)?;
    let result = command(&mut c, &cli.cmd);
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
            println!("build {}", env!("KXPROV_BUILD_HASH"));
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
        Command::Unlock { .. } | Command::Mode { .. } | Command::SimMark { .. } => {
            unreachable!("handled earlier")
        }
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
    let ModeCommand::Set { mode, profile } = cmd;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Usage(e.to_string()))?;
    rt.block_on(async {
        let mut c = kxprov_api::ApiClient::connect(&cli.socket)
            .await
            .map_err(|e| CliError::Usage(e.to_string()))?;
        let kxprov_api::ResponseResult::SetMode(r) = c
            .call(kxprov_api::RequestBody::SetMode {
                params: SetModeParams {
                    mode: (*mode).into(),
                    profile: (*profile).into(),
                },
            })
            .await
            .map_err(|e| CliError::Usage(e.to_string()))?
        else {
            return Err(CliError::Usage("unexpected response".into()));
        };
        println!(
            "mode={:?} profile={:?} counter={}",
            r.mode, r.profile, r.counter
        );
        Ok(())
    })
}

fn sim_mark(cli: &Cli) -> Result<(), CliError> {
    let Command::SimMark { cmd } = &cli.cmd else {
        return Err(CliError::Usage("sim-mark".into()));
    };
    match cmd {
        SimMarkCommand::Status { data_dir } => {
            let path = data_dir.join("sim-mark.json");
            if !path.exists() {
                println!("marked=false build={}", env!("KXPROV_BUILD_HASH"));
                return Ok(());
            }
            let raw = std::fs::read_to_string(&path).map_err(|e| CliError::Usage(e.to_string()))?;
            let v: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| CliError::Usage(e.to_string()))?;
            let hash = v["build_hash"].as_str().unwrap_or("");
            let marked = hash == env!("KXPROV_BUILD_HASH");
            println!(
                "marked={marked} build={} stored={hash}",
                env!("KXPROV_BUILD_HASH")
            );
            Ok(())
        }
        SimMarkCommand::Write { data_dir } => {
            let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..");
            let status = std::process::Command::new("cargo")
                .current_dir(&workspace)
                .args([
                    "test",
                    "-p",
                    "kxtd1232-sim",
                    "-p",
                    "kxprovd",
                    "--lib",
                    "--tests",
                ])
                .status()
                .map_err(|e| CliError::Usage(e.to_string()))?;
            if !status.success() {
                return Err(CliError::Usage("simulator tests failed".into()));
            }
            std::fs::create_dir_all(data_dir).map_err(|e| CliError::Usage(e.to_string()))?;
            let mark = serde_json::json!({
                "build_hash": env!("KXPROV_BUILD_HASH"),
                "marked_at_ms": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            });
            let bytes = serde_json::to_vec_pretty(&mark).map_err(|e| CliError::Usage(e.to_string()))?;
            std::fs::write(data_dir.join("sim-mark.json"), bytes)
                .map_err(|e| CliError::Usage(e.to_string()))?;
            println!("sim-mark written for build {}", env!("KXPROV_BUILD_HASH"));
            Ok(())
        }
    }
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
