//! `kxprov`: kx-provision CLI. A1 scope: simulator only, read-only and dry-run.
//!
//! Exit codes: 0 success; 1 runtime error, including a refused plan (for example a table
//! outside the write allow-list) and protocol, frame or login failures; 2 usage error
//! (bad arguments, out-of-range records, invalid field values). Errors print one line,
//! `kxprov: error: ...`, with no backtrace.

use clap::{Parser, Subcommand, ValueEnum};
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

/// Command result plus any close (end-binary) failure, which is always reported.
fn run(cli: &Cli) -> (Result<(), CliError>, Option<Error>) {
    if let Err(e) = check_ranges(&cli.cmd) {
        return (Err(e), None);
    }
    let TransportKind::Sim = cli.transport;
    let mut c = Client::new(SimTransport::new(SimPbx::default()));
    if let Err(e) = c.login(PLACEHOLDER_PASSWORD) {
        return (Err(e.into()), None);
    }
    let result = command(&mut c, &cli.cmd);
    // Always try to leave binary mode, and never hide a failure to do so.
    (result, c.end_binary().err())
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

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) if !e.use_stderr() => {
            // --help / --version
            print!("{e}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            let msg = e.to_string();
            let mut lines = msg.lines().map(str::trim).filter(|l| !l.is_empty());
            let first = lines.next().unwrap_or("usage error");
            let mut text = first.strip_prefix("error: ").unwrap_or(first).to_string();
            if text.ends_with(':') {
                if let Some(next) = lines.next() {
                    text = format!("{text} {next}");
                }
            }
            eprintln!("kxprov: error: {text} (see kxprov --help)");
            return ExitCode::from(2);
        }
    };
    let (result, close) = run(&cli);
    let (code, lines) = report(&result, close.as_ref());
    for l in lines {
        eprintln!("{l}");
    }
    ExitCode::from(code)
}

/// Exit code and stderr lines. A close failure is always printed, after the command's own
/// error if there is one, and turns success into exit 1.
fn report(result: &Result<(), CliError>, close: Option<&Error>) -> (u8, Vec<String>) {
    let mut code = 0;
    let mut lines = Vec::new();
    if let Err(e) = result {
        lines.push(format!("kxprov: error: {e}"));
        code = e.code();
    }
    if let Some(e) = close {
        lines.push(format!("kxprov: error: closing session: {e}"));
        if code == 0 {
            code = 1;
        }
    }
    (code, lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_error_is_reported_after_success() {
        let (code, lines) = report(&Ok(()), Some(&Error::EndBinaryHeld));
        assert_eq!(code, 1);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("kxprov: error: closing session: "));
    }

    #[test]
    fn close_error_is_not_hidden_by_command_error() {
        let (code, lines) = report(
            &Err(CliError::Runtime(Error::Timeout)),
            Some(&Error::EndBinaryHeld),
        );
        assert_eq!(code, 1);
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("closing session"));
    }

    #[test]
    fn close_is_attempted_and_fails_on_a_dead_link() {
        // A real client whose end-binary cannot be sent: the close error surfaces.
        let mut t = SimTransport::new(SimPbx::default());
        t.drop_link_after_write = true;
        let mut c = Client::with(t, kxtd1232::frame::Access::ReadWrite, Default::default());
        c.login(PLACEHOLDER_PASSWORD).expect("login");
        let _ = c.write(0x25, 0, 0, &[0x41; 16]);
        let close = c.end_binary().err();
        let (code, lines) = report(&Ok(()), close.as_ref());
        assert_eq!(code, 1, "{lines:?}");
    }
}
