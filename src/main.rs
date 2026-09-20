use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use clap::Parser;
use nginxlint::{lint, parse, render, Severity};

/// Lints an nginx config file for common misconfigurations.
#[derive(Parser)]
#[command(name = "nginxlint", version, about)]
struct Cli {
    /// Path to the nginx config file. Reads stdin if omitted.
    path: Option<String>,

    /// Exit 0 even if warnings/errors are found (still prints them).
    #[arg(long)]
    no_fail: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let (label, text) = match &cli.path {
        Some(path) => match fs::read_to_string(path) {
            Ok(text) => (path.clone(), text),
            Err(e) => {
                eprintln!("nginxlint: failed to read {path}: {e}");
                return ExitCode::from(2);
            }
        },
        None => {
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("nginxlint: failed to read stdin: {e}");
                return ExitCode::from(2);
            }
            ("<stdin>".to_string(), buf)
        }
    };

    let items = parse(&text);
    let findings = lint(&items);
    let report = render(&findings, &label);

    let mut stdout = io::stdout();
    if stdout.write_all(report.as_bytes()).is_err() {
        return ExitCode::from(0);
    }

    if cli.no_fail || findings.is_empty() {
        return ExitCode::from(0);
    }
    let has_error = findings.iter().any(|f| f.severity == Severity::Error);
    ExitCode::from(if has_error { 2 } else { 1 })
}
