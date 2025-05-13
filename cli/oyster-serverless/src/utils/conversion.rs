use alloy::primitives::U256;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};

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

pub fn iso8601_to_epoch(iso8601_string: &str) -> Result<i64, chrono::ParseError> {
    let native_date = NaiveDateTime::parse_from_str(iso8601_string, "%Y-%m-%dT%H:%M:%S")?;
    let datetime_utc = DateTime::<Utc>::from_naive_utc_and_offset(native_date, Utc);
    let epoch_seconds = datetime_utc.timestamp();
    Ok(epoch_seconds)
}
