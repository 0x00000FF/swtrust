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
        Ok(ParseOutcome::RecordIntegrity(c)) => {
            // The packaging step of FIPS 140-3 clause 10.3.1: the value the
            // pre-operational test compares against is written once, by
            // whoever installs the module, rather than by the module the first
            // time it happens to run.
            if let Err(e) = std::fs::create_dir_all(&c.state_dir) {
                eprintln!("swtrust: cannot create the state directory: {e}");
                return ExitCode::FAILURE;
            }
            let at = c.state_dir.join("integrity.hex");
            match swtrust::tpm::fips::record_integrity(&at) {
                Ok(mac) => {
                    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
                    println!("{hex}  {}", at.display());
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("swtrust: cannot record the integrity value: {}", e.0);
                    return ExitCode::FAILURE;
                }
            }
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
