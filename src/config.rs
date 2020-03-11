use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use derive_more::Display;
use serde_derive::Deserialize;
use syslog;

use crate::acl::{Acl, AclAction, AclItem};

#[derive(Debug, Display)]
pub enum ConfigError {
    IoError(std::io::Error),
    DeserializationError(toml::de::Error),
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::DeserializationError(e)
    }
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

#[derive(Debug, Deserialize, Clone, Copy)]
#[allow(non_camel_case_types)]
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

impl Into<syslog::Facility> for SyslogFacility {
    fn into(self) -> syslog::Facility {
        use syslog::Facility::*;
        use SyslogFacility::*;

        match self {
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

#[derive(Debug, Deserialize, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum LogLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::INFO
    }
}

impl Into<log::LevelFilter> for LogLevel {
    fn into(self) -> log::LevelFilter {
        match self {
            LogLevel::ERROR => log::LevelFilter::Error,
            LogLevel::WARN => log::LevelFilter::Warn,
            LogLevel::INFO => log::LevelFilter::Info,
            LogLevel::DEBUG => log::LevelFilter::Debug,
            LogLevel::TRACE => log::LevelFilter::Trace,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SyslogConfig {
    pub facility: SyslogFacility,
    #[serde(default)]
    pub level: LogLevel,
}

impl SyslogConfig {
    pub fn initialize_logging(&self) {
        syslog::init(
            self.facility.into(),
            self.level.into(),
            Some(env!("CARGO_PKG_NAME")),
        )
        .expect("failed to initialize syslog");
    }
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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
    #[serde(alias = "stats-socket-listen-address")]
    pub stats_socket_listen_address: Option<String>,
    #[serde(alias = "expect-proxy", default = "_false")]
    pub expect_proxy: bool,
    #[serde(alias = "reuse-port", default = "_false")]
    pub reuse_port: bool,
    pub syslog: Option<SyslogConfig>,
}

impl RawConfig {
    fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut f = File::open(path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;
        let config = toml::from_str(contents.as_str())?;
        Ok(config)
    }
}

pub struct Config {
    pub listen_address: ListenAddress,
    pub bind_addresses: Vec<IpAddr>,
    pub acl: Acl,
    pub connect_timeout_ms: u32,
    pub total_timeout_ms: Option<u32>,
    pub shutdown_timeout_ms: u64,
    pub stats_socket_listen_address: Option<String>,
    pub expect_proxy: bool,
    pub reuse_port: bool,
    pub syslog_config: Option<SyslogConfig>,
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let raw = RawConfig::from_path(path)?;
        Ok(Config {
            listen_address: raw.listen_address,
            bind_addresses: raw.bind_addresses,
            acl: Acl::from_parts(raw.acl, raw.acl_default_action),
            connect_timeout_ms: raw.connect_timeout_ms.unwrap_or(10_000),
            total_timeout_ms: raw.total_timeout_ms,
            shutdown_timeout_ms: u64::from(raw.shutdown_timeout_ms.unwrap_or(5_000)),
            stats_socket_listen_address: raw.stats_socket_listen_address,
            expect_proxy: raw.expect_proxy,
            reuse_port: raw.reuse_port,
            syslog_config: raw.syslog,
        })
    }

    pub fn initialize_logging(&self) {
        if let Some(ref c) = self.syslog_config {
            c.initialize_logging()
        } else {
            env_logger::init()
        }
    }
}
