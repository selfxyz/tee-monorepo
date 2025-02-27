use crate::configs::global::{INDEXER_URL, MIN_RATE_THRESHOLD};
use anyhow::{Context, Result};
use chrono::DateTime;
use prettytable::{row, Table};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

#[derive(Debug)]
struct JobData {
    id: String,
    rate_per_hour: f64,
    current_balance: f64,
    time_remaining: f64,
    provider: String,
}

pub async fn list_jobs(wallet_address: &str, count: Option<u32>) -> Result<()> {
    info!("Listing active jobs for wallet address: {}", wallet_address);

    let client = Client::new();
    let query = json!({
        "query": r#"
            query($owner: String!) {
                allJobs(
                    filter: {
                        owner: { equalToInsensitive: $owner },
                    }
                    orderBy: CREATED_DESC
                ) {
                    nodes {
                        id
                        balance
                        lastSettled
                        rate
                        provider
                        metadata
                    }
                }
            }
        "#,
        "variables": {
            "owner": wallet_address,
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

    let nodes = data
        .get("data")
        .and_then(|data| data.get("allJobs"))
        .and_then(|all_jobs| all_jobs.get("nodes"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if nodes.is_empty() {
        info!("No active jobs found for address: {}", wallet_address);
        return Ok(());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let mut table = Table::new();
    table.add_row(row![
        "ID",
        "RATE (USDC/hour)",
        "BALANCE",
        "TIME REMAINING",
        "PROVIDER"
    ]);

    let mut printed_count = 0u32;
    for node in nodes {
        let Some(job) = process_job_data(&node, now) else {
            continue;
        };

        if let Some(max_count) = count {
            if printed_count >= max_count {
                break;
            }
        }

        table.add_row(row![
            job.id,
            format!("{:.4} USDC", job.rate_per_hour),
            format!("{:.4} USDC", job.current_balance),
            format_time_remaining(job.time_remaining),
            job.provider
        ]);
        printed_count += 1;
    }

    if printed_count == 0 {
        info!(
            "No active jobs with positive balance found for address: {}",
            wallet_address
        );
        return Ok(());
    }

    table.printstd();
    Ok(())
}

fn process_job_data(node: &Value, now: f64) -> Option<JobData> {
    let id = node
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();

    debug!(
        "Processing job {} with raw rate: {:?}",
        id,
        node.get("rate")
    );

    // Get raw rate value first to properly handle zero rates
    let rate_str = node.get("rate").and_then(|v| v.as_str())?;
    let rate_raw = rate_str.parse::<f64>().ok()?;
    let rate_per_hour = (rate_raw / 1_000_000_000_000_000_000.0) * 3600.0;

    debug!("Calculated rate: {} USDC/hour", rate_per_hour);

    // Skip if rate is zero, negative, or negligible (less than 0.01 USDC/hour)
    if rate_per_hour <= MIN_RATE_THRESHOLD {
        debug!("Skipping job {} due to rate below minimum threshold", id);
        return None;
    }

    let balance_usdc = node
        .get("balance")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .map(|n| n / 1_000_000.0)?;

    if balance_usdc <= 0.0 {
        debug!("Skipping job {} due to zero or negative balance", id);
        return None;
    }

    let last_settled = node
        .get("lastSettled")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(&format!("{s}Z")).ok())
        .map(|dt| dt.timestamp() as f64)?;

    let delta_hours = (now - last_settled) / 3600.0;
    let current_balance = balance_usdc - (delta_hours * rate_per_hour);

    if current_balance <= 0.0 {
        debug!(
            "Skipping job {} due to zero or negative current balance",
            id
        );
        return None;
    }

    let time_remaining = current_balance / rate_per_hour;

    let provider = node
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();

    Some(JobData {
        id,
        rate_per_hour,
        current_balance,
        time_remaining,
        provider,
    })
}

fn format_time_remaining(hours: f64) -> String {
    let days = (hours / 24.0).floor();
    let remaining_hours = (hours % 24.0).floor();
    let minutes = ((hours * 60.0) % 60.0).floor();

    match (days as i64, remaining_hours as i64) {
        (d, _) if d > 0 => format!("{:.0}d {:.0}h {:.0}m", days, remaining_hours, minutes),
        (0, h) if h > 0 => format!("{:.0}h {:.0}m", remaining_hours, minutes),
        _ => format!("{:.0}m", minutes),
    }
}
