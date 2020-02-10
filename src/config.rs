use std::fs::File;
use std::path::Path;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use derive_more::Display;
use serde_derive::Deserialize;
use ip_network::IpNetwork;


#[derive(Debug, Display)]
pub enum ConfigError {
    IoError(std::io::Error),
    DeserializationError(toml::de::Error),
}

impl std::error::Error for ConfigError { }

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
pub enum AclAction {
    Allow,
    Reject
}

impl AclAction {
    fn permitted(&self) -> bool {
        match self {
            AclAction::Allow => true,
            AclAction::Reject => false
        }
    }
}

impl Default for AclAction {
    fn default() -> Self {
        AclAction::Allow
    }
}

#[derive(Debug, Deserialize)]
pub struct AclItem {
    pub action: AclAction,
    pub destination_network: Option<IpNetwork>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(alias = "listen-address")]
    pub listen_address: String,
    #[serde(alias = "bind-addresses", default="_default_bind")]
    pub bind_addresses: Vec<IpAddr>,
    pub acl: Vec<AclItem>,
    #[serde(alias="acl-default-action")]
    pub acl_default_action: AclAction,
    #[serde(alias = "connect-timeout-ms", default="_default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(alias = "total-timeout-ms")]
    pub total_timeout_ms: Option<u32>,
}


impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut f = File::open(path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;
        let config = toml::from_str(contents.as_str())?;
        Ok(config)
    }

    pub fn is_permitted(&self, ip: IpAddr, dport: u16) -> bool {
        for rule in self.acl.iter() {
            let ip_match = rule.destination_network.map(|i| i.contains(ip)).unwrap_or(true);
            let port_match = rule.destination_port.map(|p| p == dport).unwrap_or(true);
            if ip_match && port_match {
                return rule.action.permitted()
            }
        }
        self.acl_default_action.permitted()
    }
}
