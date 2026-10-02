#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use inlet_guard::{Decision, Policy, Report, RequestEnvelope, canonical_json_sha256, evaluate};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Evaluate one request envelope.
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long, value_enum, default_value_t = Output::Human)]
        output: Output,
    },
    /// Evaluate newline-delimited request envelopes from a file or standard input.
    Batch {
        #[arg(long)]
        policy: PathBuf,
        /// JSONL input path. Omit to read standard input.
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Output::Json)]
        output: Output,
    },
    /// Compute the canonical SHA-256 digest for a JSON arguments object.
    DigestArgs {
        #[arg(long)]
        arguments: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Output {
    Human,
    Json,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check {
            policy,
            request,
            output,
        } => {
            let policy: Policy = read_json(&policy)?;
            let request: RequestEnvelope = read_json(&request)?;
            let report = evaluate(&policy, &request)?;
            print_report(&report, output)?;
            Ok(decision_exit(&report.decision))
        }
        Command::Batch {
            policy,
            input,
            output,
        } => {
            let policy: Policy = read_json(&policy)?;
            policy.validate()?;
            let reader: Box<dyn BufRead> = match input {
                Some(path) => Box::new(io::BufReader::new(fs::File::open(path)?)),
                None => Box::new(io::BufReader::new(io::stdin())),
            };
            let mut denied = false;
            let mut count = 0_u64;
            for (index, line) in reader.lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let request: RequestEnvelope = serde_json::from_str(&line)
                    .map_err(|error| format!("JSONL line {}: {error}", index + 1))?;
                let report = evaluate(&policy, &request)?;
                denied |= report.decision == Decision::Deny;
                count += 1;
                print_report(&report, output)?;
            }
            if count == 0 {
                return Err("batch input contains no request envelopes".into());
            }
            Ok(if denied {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::DigestArgs { arguments } => {
            let value: Value = read_json(&arguments)?;
            println!("{}", canonical_json_sha256(&value));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn print_report(report: &Report, output: Output) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    match output {
        Output::Json => serde_json::to_writer(&mut handle, report)?,
        Output::Human => {
            writeln!(
                handle,
                "{} {} ({})",
                match report.decision {
                    Decision::Allow => "ALLOW",
                    Decision::Deny => "DENY",
                },
                report.request_id,
                report.policy_id
            )?;
            for finding in &report.findings {
                writeln!(handle, "- {:?}: {}", finding.code, finding.message)?;
            }
        }
    }
    if matches!(output, Output::Json) {
        writeln!(handle)?;
    }
    Ok(())
}

fn decision_exit(decision: &Decision) -> ExitCode {
    match decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Deny => ExitCode::from(2),
    }
}
