use std::fs::File;
use std::path::Path;
use std::io::Read;

use derive_more::Display;
use serde_derive::Deserialize;


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

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    #[serde(alias = "bind-address")]
    pub bind_address: String,
    #[serde(alias="disallow-private", default="_false")]
    pub disallow_private: bool
}


impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut f = File::open(path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;
        let config = toml::from_str(contents.as_str())?;
        Ok(config)
    }
}
