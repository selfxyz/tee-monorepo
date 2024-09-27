// src/args.rs
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    /// Path to the enclave log file
    #[clap(short, long)]
    pub enclave_log_file: String,

    /// Path to the script log file
    #[clap(short, long)]
    pub script_log_file: String,

    /// Target CID for the enclave (optional, default is 18)
    #[clap(short, long, default_value = "18")]
    pub target_cid: u64,
}
