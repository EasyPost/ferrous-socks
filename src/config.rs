use std::convert::TryInto;
use std::fs::File;
use std::fs::Permissions;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::acl::{Acl, AclAction, AclItem};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error reading configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("Deserialization error reading configuration: {0}")]
    Deserialization(#[from] toml::de::Error),
}

fn _true() -> bool {
    true
}

fn _false() -> bool {
    false
}

fn _default_bind() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
    ]
}

fn _default_mode() -> u32 {
    0o600
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum SyslogFacility {
    KERN,
    USER,
    MAIL,
    DAEMON,
    AUTH,
    SYSLOG,
    LPR,
    NEWS,
    UUCP,
    CRON,
    AUTHPRIV,
    FTP,
    LOCAL0,
    LOCAL1,
    LOCAL2,
    LOCAL3,
    LOCAL4,
    LOCAL5,
    LOCAL6,
    LOCAL7,
}

impl From<SyslogFacility> for syslog::Facility {
    fn from(s: SyslogFacility) -> syslog::Facility {
        use syslog::Facility::*;
        use SyslogFacility::*;

        match s {
            KERN => LOG_KERN,
            USER => LOG_USER,
            MAIL => LOG_MAIL,
            DAEMON => LOG_DAEMON,
            AUTH => LOG_AUTH,
            SYSLOG => LOG_SYSLOG,
            LPR => LOG_LPR,
            NEWS => LOG_NEWS,
            UUCP => LOG_UUCP,
            CRON => LOG_CRON,
            AUTHPRIV => LOG_AUTHPRIV,
            FTP => LOG_FTP,
            LOCAL0 => LOG_LOCAL0,
            LOCAL1 => LOG_LOCAL1,
            LOCAL2 => LOG_LOCAL2,
            LOCAL3 => LOG_LOCAL3,
            LOCAL4 => LOG_LOCAL4,
            LOCAL5 => LOG_LOCAL5,
            LOCAL6 => LOG_LOCAL6,
            LOCAL7 => LOG_LOCAL7,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum LogLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(ll: LogLevel) -> log::LevelFilter {
        match ll {
            LogLevel::ERROR => log::LevelFilter::Error,
            LogLevel::WARN => log::LevelFilter::Warn,
            LogLevel::INFO => log::LevelFilter::Info,
            LogLevel::DEBUG => log::LevelFilter::Debug,
            LogLevel::TRACE => log::LevelFilter::Trace,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyslogConfig {
    pub facility: SyslogFacility,
    pub level: Option<LogLevel>,
}

impl SyslogConfig {
    pub fn initialize_logging(&self, level: log::LevelFilter) {
        let level = self.level.map(|l| l.into()).unwrap_or(level);
        syslog::init(self.facility.into(), level, Some(env!("CARGO_PKG_NAME")))
            .expect("failed to initialize syslog");
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ListenAddress {
    One(SocketAddr),
    Several(Vec<SocketAddr>),
}

pub struct ListenAddressIter<'t> {
    inner: &'t ListenAddress,
    offset: usize,
    size: usize,
}

impl<'t> ListenAddressIter<'t> {
    fn new(inner: &'t ListenAddress) -> ListenAddressIter<'t> {
        ListenAddressIter {
            inner,
            offset: 0,
            size: match inner {
                ListenAddress::One(_) => 1,
                ListenAddress::Several(s) => s.len(),
            },
        }
    }
}

impl<'t> Iterator for ListenAddressIter<'t> {
    type Item = &'t SocketAddr;

    fn next(&mut self) -> Option<&'t SocketAddr> {
        if self.offset >= self.size {
            None
        } else {
            self.offset += 1;
            match self.inner {
                ListenAddress::Several(v) => Some(&v[self.offset - 1]),
                ListenAddress::One(i) => Some(i),
            }
        }
    }
}

impl ListenAddress {
    pub fn iter(&self) -> ListenAddressIter {
        ListenAddressIter::new(self)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    #[serde(alias = "listen-address")]
    #[serde(alias = "listen-addresses")]
    pub listen_address: ListenAddress,
    #[serde(alias = "bind-addresses", default = "_default_bind")]
    pub bind_addresses: Vec<IpAddr>,
    pub acl: Vec<AclItem>,
    #[serde(alias = "acl-default-action")]
    pub acl_default_action: AclAction,
    #[serde(alias = "connect-timeout-ms")]
    pub connect_timeout_ms: Option<u32>,
    #[serde(alias = "total-timeout-ms")]
    pub total_timeout_ms: Option<u32>,
    #[serde(alias = "shutdown-timeout-ms")]
    pub shutdown_timeout_ms: Option<u32>,
    #[serde(alias = "proxy-protocol-timeout-ms")]
    pub proxy_protocol_timeout_ms: Option<u32>,
    #[serde(alias = "stats-socket-listen-address")]
    pub stats_socket_listen_address: Option<String>,
    #[serde(alias = "stats-socket-mode", default = "_default_mode")]
    pub stats_socket_mode: u32,
    #[serde(alias = "expect-proxy", default = "_false")]
    pub expect_proxy: bool,
    #[serde(alias = "reuse-port", default = "_false")]
    pub reuse_port: bool,
    pub syslog: Option<SyslogConfig>,
}

impl Default for RawConfig {
    fn default() -> Self {
        RawConfig {
            listen_address: ListenAddress::One(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                1080,
            )),
            bind_addresses: _default_bind(),
            acl: vec![],
            acl_default_action: AclAction::Allow,
            connect_timeout_ms: None,
            total_timeout_ms: None,
            shutdown_timeout_ms: None,
            proxy_protocol_timeout_ms: None,
            stats_socket_listen_address: None,
            stats_socket_mode: _default_mode(),
            expect_proxy: false,
            reuse_port: false,
            syslog: None,
        }
    }
}

impl RawConfig {
    fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut f = File::open(path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;
        let config = toml::from_str(contents.as_str())?;
        Ok(config)
    }

    fn dump_to<W: std::io::Write>(&self, f: W) -> anyhow::Result<()> {
        let v = toml::ser::to_vec(self)?;
        let mut b = std::io::BufWriter::new(f);
        b.write_all(&v)?;
        Ok(())
    }

    /// Dump the given config to the path. If the path is None, will dump to stdout.
    pub fn dump<P: AsRef<Path>>(&self, path: Option<P>) -> anyhow::Result<()> {
        if let Some(path) = path {
            let f = File::create(path.as_ref())?;
            self.dump_to(f)
        } else {
            let stdout = std::io::stdout();
            let f = stdout.lock();
            self.dump_to(f)
        }
    }
}

pub struct Config {
    pub listen_address: ListenAddress,
    pub bind_addresses: Vec<IpAddr>,
    pub acl: Acl,
    pub connect_timeout: Duration,
    pub total_timeout: Option<Duration>,
    pub shutdown_timeout: Duration,
    pub proxy_protocol_timeout: Duration,
    pub stats_socket_listen_address: Option<String>,
    pub stats_socket_mode: Permissions,
    pub expect_proxy: bool,
    pub reuse_port: bool,
    pub syslog_config: Option<SyslogConfig>,
}

fn ms_with_default(val: Option<u32>, default: u32) -> Duration {
    Duration::from_millis(u64::from(val.unwrap_or(default)))
}

impl Default for Config {
    fn default() -> Self {
        Self::from_raw(RawConfig::default())
    }
}

impl Config {
    pub fn from_raw(raw: RawConfig) -> Self {
        Config {
            listen_address: raw.listen_address,
            bind_addresses: raw.bind_addresses,
            acl: Acl::from_parts(raw.acl, raw.acl_default_action),
            connect_timeout: ms_with_default(raw.connect_timeout_ms, 10_000),
            total_timeout: raw
                .total_timeout_ms
                .map(|d| Duration::from_millis(u64::from(d))),
            shutdown_timeout: ms_with_default(raw.shutdown_timeout_ms, 5_000),
            proxy_protocol_timeout: ms_with_default(raw.proxy_protocol_timeout_ms, 1_000),
            stats_socket_listen_address: raw.stats_socket_listen_address,
            stats_socket_mode: Permissions::from_mode(raw.stats_socket_mode),
            expect_proxy: raw.expect_proxy,
            reuse_port: raw.reuse_port,
            syslog_config: raw.syslog,
        }
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let raw = RawConfig::from_path(path)?;
        Ok(Self::from_raw(raw))
    }

    fn into_raw(self) -> RawConfig {
        let (acl, acl_default_action) = self.acl.into_parts();
        RawConfig {
            listen_address: self.listen_address,
            bind_addresses: self.bind_addresses,
            acl,
            acl_default_action,
            connect_timeout_ms: Some(self.connect_timeout.as_millis().try_into().unwrap()),
            total_timeout_ms: self
                .total_timeout
                .map(|d| d.as_millis().try_into().unwrap()),
            shutdown_timeout_ms: Some(self.shutdown_timeout.as_millis().try_into().unwrap()),
            proxy_protocol_timeout_ms: Some(
                self.proxy_protocol_timeout.as_millis().try_into().unwrap(),
            ),
            stats_socket_listen_address: self.stats_socket_listen_address,
            stats_socket_mode: self.stats_socket_mode.mode(),
            expect_proxy: self.expect_proxy,
            reuse_port: self.reuse_port,
            syslog: self.syslog_config,
        }
    }

    pub fn dump<P: AsRef<Path>>(self, path: Option<P>) -> anyhow::Result<()> {
        self.into_raw().dump(path)
    }

    pub fn initialize_logging(&self, matches: &clap::ArgMatches) {
        let level: log::LevelFilter = matches
            .value_of_t_or_exit::<String>("log_level")
            .parse()
            .expect("Invalid --log-level");
        // this is gross but semantically equivalnet to the illegal `if let Some(ref c) = self.syslog_config && !matches.is_present("stderr")`
        if let Some(c) = (!matches.is_present("stderr"))
            .then(|| self.syslog_config.as_ref())
            .flatten()
        {
            c.initialize_logging(level)
        } else {
            env_logger::Builder::new()
                .filter_level(level)
                .format_timestamp_secs()
                .init();
        }
    }
}
