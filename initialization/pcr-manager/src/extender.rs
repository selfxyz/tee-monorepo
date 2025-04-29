use clap::Parser;

/// Extend PCRs
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PCR index, should be within [16, 31] inclusive
    #[arg(short, long)]
    index: String,

    /// path to file whose contents to extend the PCR with
    #[arg(short, long)]
    contents_path: String,
}

fn main() {
    println!("Hello, world!");
}
