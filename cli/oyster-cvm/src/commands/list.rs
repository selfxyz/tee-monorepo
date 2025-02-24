use anyhow::{Context, Result};
use crate::configs::global::INDEXER_URL;
use prettytable::{row, Table};
use reqwest;
use serde_json::{json, Value};
use tracing::info;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn list_jobs(wallet_address: &str) -> Result<()> {
    info!("Listing active jobs for wallet address: {}", wallet_address);

    let client = reqwest::Client::new();

    let query = json!({
        "query": r#"
            query($owner: String!) {
                allJobs(filter: { 
                    isClosed: { equalTo: false }, 
                    owner: { equalTo: $owner }
                }) {
                    edges {
                        node {
                            id
                            balance
                            created
                            isClosed
                            lastSettled
                            metadata
                            nodeId
                            owner
                            provider
                            rate
                        }
                    }
                }
            }
        "#,
        "variables": {
            "owner": wallet_address
        }
    });

    let response = client
        .post(INDEXER_URL)
        .json(&query)
        .send()
        .await
        .context("Failed to send GraphQL query")?;

    let data: Value = response
        .json()
        .await
        .context("Failed to parse GraphQL response")?;

    if let Some(errors) = data.get("errors") {
        anyhow::bail!("GraphQL query failed: {:?}", errors);
    }

    let edges = data
        .get("data")
        .and_then(|data| data.get("allJobs"))
        .and_then(|all_jobs| all_jobs.get("edges"))
        .and_then(Value::as_array);

    if let Some(edges_array) = edges {
        if edges_array.is_empty() {
            info!("No active jobs found for address: {}", wallet_address);
            return Ok(());
        }

        // Create a table using prettytable-rs
        let mut table = Table::new();
        table.add_row(row!["ID", "RATE (USDC/hour)", "BALANCE", "PROVIDER"]);

        // Compute the current time once as seconds since Unix epoch.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        for edge in edges_array {
            if let Some(node) = edge.get("node") {
                let id = node.get("id").and_then(Value::as_str).unwrap_or("N/A");
                let rate = node
                    .get("rate")
                    .and_then(Value::as_str)
                    .map(|r| {
                        if let Ok(num) = r.parse::<f64>() {
                            // Convert rate from USDC/second to USDC/hour
                            let usdc = (num / 1_000_000_000_000_000_000.0) * 3600.0;
                            format!("{:.4} USDC", usdc)
                        } else {
                            "N/A".to_string()
                        }
                    })
                    .unwrap_or_else(|| "N/A".to_string());

                // --- Modified Balance Calculation ---
                let balance_usdc_opt = node
                    .get("balance")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|n| n / 1_000_000.0);
                let rate_usdc_hour_opt = node
                    .get("rate")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|n| (n / 1_000_000_000_000_000_000.0) * 3600.0);
                let last_settled_opt = node
                    .get("lastSettled")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<f64>().ok());

                let balance_str = if let Some(balance_usdc) = balance_usdc_opt {
                    if let (Some(rate_usdc_hour), Some(last_settled)) =
                        (rate_usdc_hour_opt, last_settled_opt)
                    {
                        // Compute time since last update in hours.
                        let delta_hours = (now - last_settled) / 3600.0;
                        format!("{:.4} USDC", balance_usdc - (delta_hours * rate_usdc_hour))
                    } else {
                        format!("{:.4} USDC", balance_usdc)
                    }
                } else {
                    "N/A".to_string()
                };
                // --- End Modified Balance Calculation ---

                let provider = node.get("provider").and_then(Value::as_str).unwrap_or("N/A");

                table.add_row(row![id, rate, balance_str, provider]);
            }
        }

        table.printstd();
    } else {
        info!("No active jobs found for address: {}", wallet_address);
    }

    Ok(())
}
