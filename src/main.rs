use std::process::ExitCode;

use swtrust::cli::{self, ParseOutcome};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match cli::parse(&args) {
        Ok(ParseOutcome::Help) => {
            print!("{}", cli::HELP);
            return ExitCode::SUCCESS;
        }
        Ok(ParseOutcome::Version) => {
            println!("swtrust {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Ok(ParseOutcome::Run(c)) => *c,
        Err(e) => {
            eprintln!("swtrust: {e}");
            eprintln!("Run 'swtrust --help' for usage.");
            return ExitCode::FAILURE;
        }
    };

    match swtrust::run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("swtrust: {e}");
            ExitCode::FAILURE
        }
    }
}
