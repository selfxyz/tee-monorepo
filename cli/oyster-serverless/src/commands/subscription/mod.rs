mod create;
mod fetch;
mod types;
mod update;
mod utils;

pub use types::{SubscriptionArgs, SubscriptionCommands};

use anyhow::Result;

/// Run the subscription command based on args
pub async fn run_subscription(args: SubscriptionArgs) -> Result<()> {
    match args.command {
        SubscriptionCommands::Create(create_args) => create::create_subscription(create_args).await,
        SubscriptionCommands::FetchResponse(fetch_args) => fetch::fetch_response(fetch_args).await,
        SubscriptionCommands::Update(update_args) => update::update_subscription(update_args).await,
    }
}
