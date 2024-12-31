use crate::commands::bandwidth::{calculate_bandwidth_cost, get_bandwidth_rate_for_region};
use anyhow::{anyhow, Context, Result};
use ethers::contract::abigen;
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::LocalWallet;
use ethers::types::{Address, H256, U256};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::info;

// Network Configuration Constants
const ARBITRUM_ONE_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";
const JOB_REFRESH_ENDPOINT: &str = "https://sk.arb1.marlin.org/operators/jobs/refresh/ArbOne/";
const CHAINLINK_ETH_USD_FEED: &str = "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612";
const MAINNET_OPERATOR_LIST_URL: &str = "https://sk.arb1.marlin.org/operators/spec/ArbOne";

// Contract Addresses
const OYSTER_MARKET_ADDRESS: &str = "0x9d95D61eA056721E358BC49fE995caBF3B86A34B"; // Mainnet Contract Address
const USDC_ADDRESS: &str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"; // Mainnet USDC Address

const MAX_RETRIES: u32 = 10;
const BACKOFF_DURATION: u64 = 120;

// Generate type-safe contract bindings
abigen!(
    ChainlinkPriceFeed, "./src/abis/chainlink_abi.json",
    event_derives(serde::Serialize, serde::Deserialize);

    USDC, "./src/abis/token_abi.json",
    event_derives(serde::Serialize, serde::Deserialize);

    OysterMarket, "./src/abis/oyster_market_abi.json",
    event_derives(serde::Serialize, serde::Deserialize)
);

#[derive(Serialize, Deserialize)]
struct Operator {
    allowed_regions: Vec<String>,
    min_rates: Vec<RateCard>,
}

#[derive(Serialize, Deserialize)]
struct RateCard {
    region: String,
    rate_cards: Vec<InstanceRate>,
}

#[derive(Serialize, Deserialize, Clone)]
struct InstanceRate {
    instance: String,
    min_rate: String,
    cpu: u32,
    memory: u32,
    arch: String,
}

pub async fn deploy_oyster_instance(
    cpu: u32,
    memory: u32,
    image_url: &str,
    region: &str,
    wallet_private_key: &str,
    operator: &str,
    instance_type: &str,
    bandwidth: u32,
    duration: u32,
    platform: &str,
) -> Result<()> {
    tracing::info!("Starting deployment...");

    let operators = fetch_operators(MAINNET_OPERATOR_LIST_URL)
        .await
        .context("Failed to fetch operator list")?;
    let selected_operator = operators
        .into_iter()
        .find(|(addr, _)| addr.to_lowercase() == operator.to_lowercase())
        .map(|(_, operator)| operator)
        .context("Error: Operator not found in operator list")?;

    // Setup wallet and provider
    let wallet =
        LocalWallet::from_bytes(&hex::decode(wallet_private_key)?)?.with_chain_id(42161u64);
    let provider = Provider::<Http>::try_from(ARBITRUM_ONE_RPC_URL)?;
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));

    // Fetch operator min rates
    let min_rate = find_minimum_rate_instance(
        &selected_operator,
        region,
        instance_type,
        cpu,
        memory,
        platform,
    )
    .context("failed to fetch operator min rate")?;

    // Calculate costs
    let duration_seconds = (duration as u64) * 60;
    let (total_cost, total_rate) = calculate_total_cost(
        &min_rate,
        duration_seconds,
        bandwidth,
        region,
        provider.clone(),
        CHAINLINK_ETH_USD_FEED.parse()?,
    )
    .await?;

    info!(
        "Total cost: {:.6} USDC",
        total_cost.as_u128() as f64 / 1_000_000.0
    );
    info!(
        "Total rate: {:.6} ETH/hour",
        total_rate.as_u128() as f64 / 1e18
    );

    // Create metadata
    let metadata = create_metadata(instance_type, region, memory, cpu, image_url, "oyster_job");

    // Approve USDC and create job
    approve_usdc(total_cost, client.clone()).await?;
    let job_id = create_new_oyster_job(
        metadata,
        operator.parse::<Address>()?,
        total_rate,
        total_cost,
        client.clone(),
    )
    .await?;

    // Wait for IP and attestation
    info!("Job created with ID: {:?}", job_id);
    let url = format!("{}{:?}", JOB_REFRESH_ENDPOINT, job_id);
    info!("Waiting for enclave to start...");

    loop {
        let ip_address = wait_for_ip_address(&url).await?;
        if ping_ip(&ip_address).await {
            if check_attestation(&ip_address).await {
                info!("Enclave is ready! IP address: {}", ip_address);
                return Ok(());
            }
            info!("Waiting for attestation...");
        }
        tokio::time::sleep(StdDuration::from_secs(5)).await;
    }
}

async fn approve_usdc(
    amount: U256,
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<()> {
    let usdc_address: Address = USDC_ADDRESS.parse()?;
    let usdc = USDC::new(usdc_address, client.clone());
    let market_address: Address = OYSTER_MARKET_ADDRESS.parse()?;

    let approve_call = usdc.approve(market_address, amount);
    let estimated_gas = approve_call.estimate_gas().await?;
    let buffered_gas = estimated_gas + (estimated_gas / 5);

    // Get current gas price and add 20% buffer
    let gas_price = client.get_gas_price().await?;
    let buffered_gas_price = gas_price + (gas_price / 5); // Add 20% to gas price

    info!("Gas price: {} wei", gas_price);
    info!("Buffered gas price: {} wei", buffered_gas_price);
    info!("Total gas cost: {} wei", buffered_gas_price * estimated_gas);
    info!(
        "USDC approval gas estimate: {} wei ({:.6} ETH)",
        estimated_gas,
        estimated_gas.as_u128() as f64 / 1e18
    );
    info!(
        "With 20% buffer: {} wei ({:.6} ETH)",
        buffered_gas,
        buffered_gas.as_u128() as f64 / 1e18
    );

    let tx_call = approve_call.gas(buffered_gas).gas_price(buffered_gas_price); // Use buffered gas price
    let tx = tx_call.send().await?;

    info!("USDC approval transaction: {:?}", tx.tx_hash());
    tx.await?;
    Ok(())
}

async fn create_new_oyster_job(
    metadata: String,
    provider: Address,
    rate: U256,
    balance: U256,
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<H256> {
    let market_address = OYSTER_MARKET_ADDRESS.parse::<Address>()?;

    let method_call = OysterMarket::new(market_address, client.clone())
        .job_open(metadata, provider, rate, balance);

    let estimated_gas = method_call.estimate_gas().await?;
    let buffered_gas = estimated_gas + (estimated_gas / 5);

    let gas_price = client.get_gas_price().await?;
    let buffered_gas_price = gas_price + (gas_price / 5);

    info!("Gas price: {} wei", gas_price);
    info!("Buffered gas price: {} wei", buffered_gas_price);
    info!("Total gas cost: {} wei", buffered_gas_price * estimated_gas);
    info!(
        "Job creation gas estimate: {} wei ({:.6} ETH)",
        estimated_gas,
        estimated_gas.as_u128() as f64 / 1e18
    );
    info!(
        "With 20% buffer: {} wei ({:.6} ETH)",
        buffered_gas,
        buffered_gas.as_u128() as f64 / 1e18
    );

    let tx_call = method_call.gas(buffered_gas).gas_price(buffered_gas_price);
    let pending_tx = tx_call.send().await?;

    info!("Job creation transaction: {:?}", pending_tx.tx_hash());

    // Wait for 3 minutes before checking for receipt
    info!("Waiting 3 minutes for transaction confirmation...");
    tokio::time::sleep(Duration::from_secs(180)).await;

    let receipt = pending_tx
        .await?
        .ok_or_else(|| anyhow!("No receipt found"))?;

    // Add logging to check transaction status
    if !receipt.status.unwrap_or_default().is_zero() {
        info!("Transaction successful!");
    } else {
        return Err(anyhow!("Transaction failed - check contract interaction"));
    }

    // Log all events for debugging in more detail
    info!("Transaction events:");
    for (idx, log) in receipt.logs.iter().enumerate() {
        info!("Log #{}", idx);
        info!("  Address: {:?}", log.address);
        info!("  Topics: {:?}", log.topics);
        info!("  Data: 0x{}", hex::encode(&log.data));
    }

    // Parse the JobOpened event to get the correct job ID
    let job_opened_topic =
        H256::from_str("caf4e46d4e6467895056ca2f41d879c0cd4f68875400a55b8e9b24c9904931b4")?;
    for log in receipt.logs.iter() {
        if log.topics[0] == job_opened_topic {
            // This is the JobOpened event
            info!("Found JobOpened event");
            // The job ID is in topics[1]
            return Ok(log.topics[1]);
        }
    }

    // If we can't find the JobOpened event
    info!("No JobOpened event found. All topics:");
    for log in receipt.logs.iter() {
        info!("Event topics: {:?}", log.topics);
    }

    Err(anyhow!(
        "Could not find JobOpened event in transaction receipt"
    ))
}

async fn fetch_operators(url: &str) -> Result<Vec<(String, Operator)>> {
    let client: Client = Client::new();
    let response = client.get(url).send().await?;
    let operators_map: HashMap<String, Operator> = response.json().await?;
    Ok(operators_map.into_iter().collect())
}

async fn wait_for_ip_address(url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let json: serde_json::Value = response.json().await?;

    // Add debug logging
    info!("Response from refresh endpoint: {:?}", json);

    // More robust IP extraction
    if let Some(job) = json.get("job") {
        if let Some(ip) = job.get("ip").and_then(|ip| ip.as_str()) {
            return Ok(ip.to_string());
        }
    }

    // Try direct ip field if job.ip is not found
    if let Some(ip) = json.get("ip").and_then(|ip| ip.as_str()) {
        return Ok(ip.to_string());
    }

    Err(anyhow!(
        "IP address not found in response. Response structure: {:?}",
        json
    ))
}

async fn ping_ip(ip: &str) -> bool {
    let address = format!("{}:1300", ip);
    for _ in 0..3 {
        if tokio::time::timeout(StdDuration::from_secs(2), TcpStream::connect(&address))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(StdDuration::from_secs(2)).await;
    }
    false
}

async fn check_attestation(ip: &str) -> bool {
    let response = reqwest::Client::new()
        .get(format!("http://{}:1300/attestation/raw", ip))
        .send()
        .await;

    match response {
        Ok(r) if r.status().is_success() => r.bytes().await.map_or(false, |b| !b.is_empty()),
        _ => false,
    }
}

fn create_metadata(
    instance: &str,
    region: &str,
    memory: u32,
    vcpu: u32,
    url: &str,
    name: &str,
) -> String {
    serde_json::json!({
        "instance": instance,
        "region": region,
        "memory": memory,
        "vcpu": vcpu,
        "url": url,
        "name": name
    })
    .to_string()
}

fn find_minimum_rate_instance(
    operator: &Operator,
    region: &str,
    instance: &str,
    vcpu: u32,
    memory: u32,
    arch: &str,
) -> Result<InstanceRate> {
    operator.min_rates.iter().find_map(|rate_card| {
        if rate_card.region == region {
            let matching_rates: Vec<InstanceRate> = rate_card
                .rate_cards
                .iter()
                .filter(|instance_rate| {
                    instance_rate.instance == instance
                        && instance_rate.cpu == vcpu
                        && instance_rate.memory == memory
                        && instance_rate.arch == arch
                })
                .cloned()
                .collect();

            if !matching_rates.is_empty() {
                return Some(
                    matching_rates
                        .into_iter()
                        .min_by(|a, b| {
                            let a_rate = U256::from_str_radix(a.min_rate.trim_start_matches("0x"), 16)
                                .unwrap_or(U256::max_value());
                            let b_rate = U256::from_str_radix(b.min_rate.trim_start_matches("0x"), 16)
                                .unwrap_or(U256::max_value());
                            a_rate.cmp(&b_rate)
                        })
                        .unwrap(),
                );
            }
        }
        None
    })
    .with_context(|| format!(
        "No matching instance rate found for region: {}, instance: {}, vcpu: {}, memory: {}, arch: {}",
        region, instance, vcpu, memory, arch
    ))
}

async fn calculate_total_cost(
    instance_rate: &InstanceRate,
    duration: u64,
    bandwidth: u32,
    region: &str,
    provider: Provider<Http>,
    price_feed_address: Address,
) -> Result<(U256, U256)> {
    let instance_hourly_rate_eth =
        U256::from_str_radix(instance_rate.min_rate.trim_start_matches("0x"), 16)?;

    let instance_hourly_rate_scaled = U256::from(
        retry_with_backoff(
            || async {
                convert_eth_to_usdc(
                    provider.clone(),
                    price_feed_address,
                    instance_hourly_rate_eth.as_u64(),
                )
                .await
            },
            MAX_RETRIES,
            Duration::from_secs(BACKOFF_DURATION),
        )
        .await?,
    );

    let instance_secondly_rate_scaled = instance_hourly_rate_scaled / 3600;
    let instance_cost_scaled = U256::from(duration) * instance_secondly_rate_scaled;

    let bandwidth_rate_region = get_bandwidth_rate_for_region(region);
    let bandwidth_cost_scaled = U256::from(calculate_bandwidth_cost(
        &bandwidth.to_string(),
        "kbps",
        bandwidth_rate_region,
        duration,
    ));

    let bandwidth_rate_scaled = bandwidth_cost_scaled / duration;
    let total_cost_scaled = (instance_cost_scaled + bandwidth_cost_scaled) / U256::exp10(12);
    let total_rate_scaled = instance_hourly_rate_eth + bandwidth_rate_scaled;

    Ok((total_cost_scaled, total_rate_scaled))
}

async fn convert_eth_to_usdc(
    provider: Provider<Http>,
    price_feed_address: Address,
    amount_eth: u64,
) -> Result<u64> {
    let client = Arc::new(provider);
    let price_feed_abi = include_bytes!("../abis/chainlink_abi.json");
    let price_feed_abi = ethers::abi::Abi::load(price_feed_abi.as_ref())?;
    let price_feed_contract = Contract::new(price_feed_address, price_feed_abi, client.clone());

    let (_, price, _, _, _) = price_feed_contract
        .method::<_, (u8, I256, U256, U256, u8)>("latestRoundData", ())?
        .call()
        .await?;
    let price_usd = U256::from(price.as_u64());
    let amount_eth = U256::from(amount_eth);
    let amount_usdc = (amount_eth * price_usd) / U256::exp10(8);

    Ok(amount_usdc.as_u64())
}

async fn retry_with_backoff<T, Fut, F>(
    mut operation: F,
    max_retries: u32,
    sleep_duration: Duration,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut retry_count = 0;
    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                retry_count += 1;
                if retry_count >= max_retries {
                    println!("Maximum retries reached. Exiting...");
                    return Err(e);
                }
                println!(
                    "Operation failed: {}. Retrying in {:?}... (Attempt {} of {})",
                    e, sleep_duration, retry_count, max_retries
                );
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }
}
