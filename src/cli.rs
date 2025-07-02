use clap::{Args, Parser, ValueEnum};
use std::fmt;
use std::path::PathBuf;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub(crate) enum CliLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for CliLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Error => "error",
                Self::Warn => "warn",
                Self::Info => "info",
                Self::Debug => "debug",
                Self::Trace => "trace",
            }
        )
    }
}

impl Into<log::LevelFilter> for CliLogLevel {
    fn into(self) -> log::LevelFilter {
        match self {
            Self::Error => log::LevelFilter::Error,
            Self::Warn => log::LevelFilter::Warn,
            Self::Info => log::LevelFilter::Info,
            Self::Debug => log::LevelFilter::Debug,
            Self::Trace => log::LevelFilter::Trace,
        }
    }
}

#[derive(Parser)]
#[command(version, about, author, long_about)]
/// This application implements both a SOCKS4 and SOCKS5 proxy. Most of the
/// configuration is done via a TOML file; use `ferrous-socks --dump-config -` to see
/// default options.
pub(crate) struct Cli {
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    pub config_path: Option<PathBuf>,
    #[arg(
        short = 'C',
        long = "check-config",
        help = "Only check config syntax and then exit",
        group = "config-action",
        default_value_t = false
    )]
    pub check_config: bool,
    #[arg(
        long = "dump-config",
        value_name = "PATH",
        help = "Dump out config (with defaults interpolated) to the given path (- meaning stdout)"
    )]
    pub dump_config: Option<String>,
    #[command(flatten, next_help_heading = "Logging options")]
    pub logging: LoggingCli,
}

#[derive(Args)]
pub(crate) struct LoggingCli {
    #[arg(short='L', long="log-level", help="Log level (only used if logging is not set to syslog in config)", default_value_t=CliLogLevel::Warn)]
    pub log_level: CliLogLevel,
    #[arg(
        short = 'E',
        long = "stderr",
        help = "Force logging to stderr",
        default_value_t = false
    )]
    pub stderr: bool,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn test_debug_assert_cli() {
        Cli::command().debug_assert();
    }
}
