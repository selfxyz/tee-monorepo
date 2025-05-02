use crate::args::wallet::WalletArgs;
use alloy::sol;
use clap::{Args, Subcommand};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RelayContract,
    "src/abis/Relay.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RelaySubscriptions,
    "src/abis/RelaySubscriptions.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/Token.json"
);

#[derive(Args)]
pub struct SubscriptionArgs {
    #[command(subcommand)]
    pub command: SubscriptionCommands,
}

#[derive(Subcommand)]
pub enum SubscriptionCommands {
    /// Create a new subscription
    Create(CreateSubscriptionArgs),
    /// Fetch response for a subscription
    FetchResponse(FetchResponseArgs),
}

#[derive(Args)]
pub struct CreateSubscriptionArgs {
    #[command(flatten)]
    pub wallet: WalletArgs,

    /// Execution environment (defaults to 1)
    #[arg(long, default_value = "1")]
    pub env: u8,

    /// Start timestamp for the subscription (epoch time in seconds)
    #[arg(long)]
    pub start_timestamp: Option<u64>,

    /// Termination timestamp for the subscription (epoch time in seconds)
    #[arg(long)]
    pub termination_timestamp: Option<u64>,

    /// How often to run the serverless code (in seconds)
    #[arg(long)]
    pub periodic_gap: Option<u64>,

    /// Maximum time allowed for executors to complete computation (in milliseconds)
    #[arg(long, required = true)]
    pub user_timeout: u64,

    /// Max gas price multiplier (e.g: 1.5, 2, 2.5)
    #[arg(long, default_value = "1.5")]
    pub max_gas_price: f64,

    /// Callback contract address
    #[arg(long, required = true)]
    pub callback_contract_address: String,

    /// Gas limit for callback function
    #[arg(long, required = true)]
    pub callback_gas_limit: u64,

    /// Address to receive compensation if subscription fails (defaults to sender's address)
    #[arg(long)]
    pub refund_account: Option<String>,

    /// Code hash from deployed JS code (transaction hash)
    #[arg(long, required = true)]
    pub code_hash: String,

    /// Code inputs for the worker
    #[arg(long, required = true)]
    pub input_file: String,
}

#[derive(Args)]
pub struct FetchResponseArgs {
    /// Subscription ID to fetch the response for
    #[arg(long, required = true)]
    pub subscription_transaction_hash: String,

    /// Stream the response
    #[arg(long)]
    pub stream: bool,
}
