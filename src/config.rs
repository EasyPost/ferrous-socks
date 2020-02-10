use std::fs::File;
use std::path::Path;
use std::io::Read;
use std::net::IpAddr;

use derive_more::Display;
use serde_derive::Deserialize;
use ip_network::IpNetwork;


#[derive(Debug, Display)]
pub(crate) enum ConfigError {
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

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum AclAction {
    Allow,
    Reject
}

#[derive(Debug, Deserialize)]
pub(crate) struct AclItem {
    pub action: AclAction,
    pub destination_network: Option<IpNetwork>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    #[serde(alias = "bind-address")]
    pub bind_address: String,
    pub acl: Vec<AclItem>,
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
                return rule.action == AclAction::Allow;
            }
        }
        true
    }
}
