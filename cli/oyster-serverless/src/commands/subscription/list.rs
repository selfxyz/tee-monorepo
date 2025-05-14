use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    commands::subscription::types::ListSubscriptionArgs,
    configs::global::{ARBITRUM_ONE_RPC_URL, INDEXER_URL, RELAY_CONTRACT_ADDRESS},
};
use alloy::{primitives::U256, providers::ProviderBuilder};
use anyhow::{Context, Result};
use prettytable::{row, Table};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use super::types::RelayContract;

#[derive(Deserialize, Debug)]
struct SubscriptionNode {
    #[serde(rename = "txHash")]
    tx_hash: String,
    #[serde(rename = "startTime")]
    start_time: String,
    #[serde(rename = "terminationTime")]
    termination_time: String,
    #[serde(rename = "periodicity")]
    periodicity: String,
}

#[derive(Deserialize, Debug)]
struct SubscriptionEdge {
    node: SubscriptionNode,
}

#[derive(Deserialize, Debug)]
struct AllSubscriptions {
    #[serde(rename = "totalCount")]
    total_count: i32,
    edges: Vec<SubscriptionEdge>,
}

#[derive(Deserialize, Debug)]
struct GraphQLResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<serde_json::Value>>,
}

fn get_current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs() as i64
}

/// List subscriptions for a given address
pub async fn list_subscriptions(args: ListSubscriptionArgs) -> Result<()> {
    // Create provider
    let rpc_url = ARBITRUM_ONE_RPC_URL
        .parse()
        .context("Failed to parse RPC URL")?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    // Parse addresses
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;

    // Create contract instance
    let contract = RelayContract::new(contract_address, provider.clone());

    let overall_timeout = contract
        .OVERALL_TIMEOUT()
        .call()
        .await
        .context("Failed to fetch overall timeout")?
        ._0;

    let _time_condition = U256::from(get_current_timestamp()) - overall_timeout;

    let client = reqwest::Client::new();

    let query = json!({
        "query": r#"
            query($address: String!) {
                allSubscriptions(
                    filter: {
                        owner: { equalToInsensitive: $address },
                    }
                ) {
                    totalCount
                    edges {
                        node {
                            txHash
                            startTime
                            terminationTime
                            periodicity
                        }
                    }
                }
            }
        "#,
        "variables": {
            "address": args.address
        }
    });

    let response = client
        .post(INDEXER_URL)
        .header("Content-Type", "application/json")
        .json(&query)
        .send()
        .await?;

    let response_data: GraphQLResponse = response.json().await?;

    if let Some(errors) = response_data.errors {
        anyhow::bail!("GraphQL query failed: {:?}", errors);
    }

    let mut table = Table::new();
    table.add_row(row![
        "Transaction hash",
        "Start time",
        "Termination time",
        "Periodicity"
    ]);

    if let Some(data) = response_data.data {
        let all_subscriptions: AllSubscriptions =
            serde_json::from_value(data["allSubscriptions"].clone())?;

        info!("Found {} subscriptions", all_subscriptions.total_count);

        for edge in all_subscriptions.edges {
            let subscription = edge.node;
            table.add_row(row![
                subscription.tx_hash,
                subscription.start_time,
                subscription.termination_time,
                subscription.periodicity
            ]);
        }
        if all_subscriptions.total_count > 0 {
            table.printstd();
        }
    }

    Ok(())
}
