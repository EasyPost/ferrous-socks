use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use derive_more::Display;
use serde_derive::Deserialize;

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

fn _default_connect_timeout_ms() -> u32 {
    3000
}

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    #[serde(alias = "listen-address")]
    pub listen_address: String,
    #[serde(alias = "bind-addresses", default = "_default_bind")]
    pub bind_addresses: Vec<IpAddr>,
    pub acl: Vec<AclItem>,
    #[serde(alias = "acl-default-action")]
    pub acl_default_action: AclAction,
    #[serde(alias = "connect-timeout-ms", default = "_default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(alias = "total-timeout-ms")]
    pub total_timeout_ms: Option<u32>,
    #[serde(alias = "stats-socket-listen-address")]
    pub stats_socket_listen_address: Option<String>,
    #[serde(alias = "expect-proxy", default = "_false")]
    pub expect_proxy: bool,
    #[serde(alias = "reuse-port", default = "_false")]
    pub reuse_port: bool,
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
    pub listen_address: String,
    pub bind_addresses: Vec<IpAddr>,
    pub acl: Acl,
    pub connect_timeout_ms: u32,
    pub total_timeout_ms: Option<u32>,
    pub stats_socket_listen_address: Option<String>,
    pub expect_proxy: bool,
    pub reuse_port: bool,
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let raw = RawConfig::from_path(path)?;
        Ok(Config {
            listen_address: raw.listen_address,
            bind_addresses: raw.bind_addresses,
            acl: Acl::from_parts(raw.acl, raw.acl_default_action),
            connect_timeout_ms: raw.connect_timeout_ms,
            total_timeout_ms: raw.total_timeout_ms,
            stats_socket_listen_address: raw.stats_socket_listen_address,
            expect_proxy: raw.expect_proxy,
            reuse_port: raw.reuse_port,
        })
    }
}
