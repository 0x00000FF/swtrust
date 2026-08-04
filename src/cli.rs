//! Command line argument parsing for the swtrust daemon.

use std::fmt;
use std::path::PathBuf;

/// Transport the daemon listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    /// TCP sockets using the TPM simulator protocol.
    Socket,
    /// Windows named pipe.
    Pipe,
    /// TCP sockets carrying a data channel and a control channel, which is what
    /// a virtual machine monitor attaches to.
    Qemu,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Interface::Socket => f.write_str("socket"),
            Interface::Pipe => f.write_str("pipe"),
            Interface::Qemu => f.write_str("qemu"),
        }
    }
}

/// Default TCP port for the command channel, matching the reference simulator.
pub const DEFAULT_COMMAND_PORT: u16 = 2321;
/// Default name of the command named pipe.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\swtrust";
/// Default listening address for the socket interface.
pub const DEFAULT_ADDRESS: &str = "127.0.0.1";

/// Parsed configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub interface: Interface,
    pub address: String,
    /// Command port. The platform port is always `port + 1`.
    pub port: u16,
    pub pipe_name: String,
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    pub verbose: bool,
    /// Run the debug console on stdin alongside the transport.
    pub console: bool,
    /// Follow the PC Client Platform TPM Profile as written, which takes
    /// away the algorithms it deprecated. See `crate::tpm::profile`.
    pub ptp: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interface: Interface::Socket,
            address: DEFAULT_ADDRESS.to_string(),
            port: DEFAULT_COMMAND_PORT,
            pipe_name: DEFAULT_PIPE_NAME.to_string(),
            state_dir: PathBuf::from("state"),
            log_dir: PathBuf::from("."),
            verbose: false,
            console: false,
            ptp: false,
        }
    }
}

/// Outcome of parsing the command line.
#[derive(Debug)]
pub enum ParseOutcome {
    Run(Box<Config>),
    Help,
    Version,
}

/// Text printed for `--help`.
pub const HELP: &str = concat!(
    "swtrust ",
    env!("CARGO_PKG_VERSION"),
    " - software TPM 2.0\n",
    "\n",
    "USAGE:\n",
    "    swtrust [OPTIONS]\n",
    "\n",
    "OPTIONS:\n",
    "    -i, --interface <socket|pipe|qemu>\n",
    "                                   Transport to listen on. Default: socket\n",
    "    -a, --address <addr>           Bind address for the socket interfaces. Default: 127.0.0.1\n",
    "    -p, --port <port>              Command port for the socket interfaces. Default: 2321\n",
    "                                   socket: the platform control port is <port> + 1.\n",
    "                                   qemu:   <port> carries commands and <port> + 1 the\n",
    "                                           control channel.\n",
    "    -n, --pipe-name <name>         Named pipe path. Default: \\\\.\\pipe\\swtrust\n",
    "    -s, --state <dir>              Directory holding the TPM state file. Default: ./state\n",
    "    -l, --log-dir <dir>            Directory for YYYY-MM-DD.log files. Default: .\n",
    "    -v, --verbose                  Also print command logs to stdout\n",
    "    -c, --console                  Run the debug console on stdin\n",
    "        --ptp                      Follow the PC Client Platform TPM Profile 1.07 as\n",
    "                                   written. SHA-1 is then not implemented, which is\n",
    "                                   what the profile requires and what BitLocker and\n",
    "                                   TPM virtual smart cards cannot work without.\n",
    "    -h, --help                     Print this help\n",
    "    -V, --version                  Print version\n",
);

/// Parse an argument list that excludes the program name.
pub fn parse<I, S>(args: I) -> Result<ParseOutcome, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut cfg = Config::default();
    let mut idx = 0;

    // Takes the value for an option, supporting both "--opt value" and "--opt=value".
    fn value(
        args: &[String],
        idx: &mut usize,
        inline: Option<&str>,
        name: &str,
    ) -> Result<String, String> {
        if let Some(v) = inline {
            return Ok(v.to_string());
        }
        *idx += 1;
        args.get(*idx)
            .cloned()
            .ok_or_else(|| format!("option {name} requires a value"))
    }

    while idx < args.len() {
        let arg = args[idx].clone();
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(v)),
            _ => (arg.clone(), None),
        };

        match name.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "-V" | "--version" => return Ok(ParseOutcome::Version),
            "-v" | "--verbose" => cfg.verbose = true,
            "--ptp" => cfg.ptp = true,
            "-c" | "--console" => cfg.console = true,
            "-i" | "--interface" => {
                let v = value(&args, &mut idx, inline, "--interface")?;
                cfg.interface = match v.to_ascii_lowercase().as_str() {
                    "socket" | "tcp" => Interface::Socket,
                    "pipe" | "named-pipe" | "namedpipe" => Interface::Pipe,
                    "qemu" | "vmm" => Interface::Qemu,
                    other => {
                        return Err(format!(
                            "unknown interface '{other}', expected 'socket', 'pipe' or 'qemu'"
                        ))
                    }
                };
            }
            "-a" | "--address" => {
                cfg.address = value(&args, &mut idx, inline, "--address")?;
            }
            "-p" | "--port" => {
                let v = value(&args, &mut idx, inline, "--port")?;
                cfg.port = v
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port '{v}'"))?;
                if cfg.port == u16::MAX {
                    return Err("port must be below 65535 to leave room for the platform port".into());
                }
            }
            "-n" | "--pipe-name" => {
                cfg.pipe_name = value(&args, &mut idx, inline, "--pipe-name")?;
            }
            "-s" | "--state" => {
                cfg.state_dir = PathBuf::from(value(&args, &mut idx, inline, "--state")?);
            }
            "-l" | "--log-dir" => {
                cfg.log_dir = PathBuf::from(value(&args, &mut idx, inline, "--log-dir")?);
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
        idx += 1;
    }

    Ok(ParseOutcome::Run(Box::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Config {
        match parse(args).expect("parse") {
            ParseOutcome::Run(c) => *c,
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn defaults_match_specification() {
        let c = run(&[]);
        assert_eq!(c.interface, Interface::Socket);
        assert_eq!(c.port, DEFAULT_COMMAND_PORT);
        assert_eq!(c.state_dir, PathBuf::from("state"));
        assert_eq!(c.log_dir, PathBuf::from("."));
        assert!(!c.verbose);
        assert!(!c.console);
    }

    #[test]
    fn the_console_is_asked_for_by_name_or_letter() {
        assert!(run(&["--console"]).console);
        assert!(run(&["-c"]).console);
        // It does not come on by itself, and it is separate from verbose.
        let c = run(&["--verbose"]);
        assert!(c.verbose);
        assert!(!c.console);
    }

    #[test]
    fn selects_pipe_interface() {
        let c = run(&["--interface", "pipe"]);
        assert_eq!(c.interface, Interface::Pipe);
        assert_eq!(c.pipe_name, DEFAULT_PIPE_NAME);
    }

    #[test]
    fn accepts_inline_values() {
        let c = run(&["--port=3000", "--state=C:/tpm", "--verbose"]);
        assert_eq!(c.port, 3000);
        assert_eq!(c.state_dir, PathBuf::from("C:/tpm"));
        assert!(c.verbose);
    }

    #[test]
    fn short_flags() {
        let c = run(&["-i", "pipe", "-n", r"\\.\pipe\x", "-s", "st", "-l", "logs", "-v"]);
        assert_eq!(c.interface, Interface::Pipe);
        assert_eq!(c.pipe_name, r"\\.\pipe\x");
        assert_eq!(c.state_dir, PathBuf::from("st"));
        assert_eq!(c.log_dir, PathBuf::from("logs"));
        assert!(c.verbose);
    }

    #[test]
    fn rejects_unknown_interface() {
        assert!(parse(["--interface", "carrier-pigeon"]).is_err());
    }

    #[test]
    fn rejects_missing_value() {
        assert!(parse(["--port"]).is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse(["--port", "notanumber"]).is_err());
        assert!(parse(["--port", "65535"]).is_err());
    }

    #[test]
    fn help_and_version() {
        assert!(matches!(parse(["--help"]).unwrap(), ParseOutcome::Help));
        assert!(matches!(parse(["-V"]).unwrap(), ParseOutcome::Version));
    }
}
