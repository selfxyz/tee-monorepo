use config::{self, ConfigError, File};
use ethers::types::H160;
use serde_derive::Deserialize;

pub struct ConfigManager {
    path: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub com_chain_id: u64,
    pub com_chain_ws_url: String,
    pub com_chain_http_url: String,
    pub gateway_contract_addr: H160,
    pub job_contract_addr: H160,
    pub start_block: u64,
    pub enclave_secret_key: String,
    pub enclave_public_key: String,
    pub epoch: u64,
    pub time_interval: u64,
}

impl ConfigManager {
    pub fn new(path: &String) -> ConfigManager {
        ConfigManager { path: path.clone() }
    }

    pub fn load_config(&self) -> Result<Config, ConfigError> {
        let settings = config::Config::builder()
            .add_source(File::with_name(self.path.as_str()))
            .build()?;
        settings.try_deserialize()
    }
}
