mod config;
use std::error::Error;

use clap::Parser;

use crate::config::ConfigManager;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(
        long,
        value_parser,
        default_value = "./oyster_serverless_gateway_config.json"
    )]
    config_file: String,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let config_manager = ConfigManager::new(&args.config_file);
    let config = config_manager.load_config().unwrap();

    Ok(())
}
