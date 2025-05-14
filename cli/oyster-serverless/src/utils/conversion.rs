use alloy::primitives::U256;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

pub fn to_eth(wei: U256) -> Result<f64> {
    let wei_f64: f64 = wei
        .to_string()
        .parse()
        .context("Failed to parse wei amount to f64")?;
    Ok(wei_f64 / 1e18)
}

pub fn to_usdc(base_units: U256) -> Result<f64> {
    let units_f64: f64 = base_units
        .to_string()
        .parse()
        .context("Failed to parse USDC base units to f64")?;
    Ok(units_f64 / 1e6)
}

pub fn string_epoch_to_utc_datetime(epoch: String) -> Result<String> {
    let epoch_i64 = epoch
        .parse::<i64>()
        .context("Failed to parse epoch string to i64")?;

    let datetime = DateTime::<Utc>::from_timestamp(epoch_i64, 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid epoch timestamp"))?;

    Ok(datetime.to_string())
}
