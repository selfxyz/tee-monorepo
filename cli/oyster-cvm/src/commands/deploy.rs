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

// Add these constants at the top with other constants
const IP_CHECK_RETRIES: u32 = 20;  // Total number of retries for IP check
const IP_CHECK_INTERVAL: u64 = 15;  // Seconds between retries
const ATTESTATION_RETRIES: u32 = 10;
const ATTESTATION_INTERVAL: u64 = 30;

// Generate type-safe contract bindings
abigen!(
    ChainlinkPriceFeed, "./src/abis/chainlink_abi.json",
    event_derives(serde::Serialize, serde::Deserialize);

    USDC, "./src/abis/token_abi.json",
    event_derives(serde::Serialize, serde::Deserialize);

    OysterMarket, "./src/abis/oyster_market_abi.json",
    event_derives(serde::Serialize, serde::Deserialize)
);

#[derive(Debug)]
pub struct DeploymentConfig {
    pub cpu: u32,
    pub memory: u32,
    pub image_url: String,
    pub region: String,
    pub instance_type: String,
    pub bandwidth: u32,
    pub duration: u32,
    pub platform: String,
    pub job_name: String,
}

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
    config: DeploymentConfig,
    wallet_private_key: &str,
    operator: &str,
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

    // Validate region is supported
    if !selected_operator.allowed_regions.iter().any(|r| r == &config.region) {
        return Err(anyhow!("Region '{}' not supported by operator", config.region));
    }

    // Setup wallet and provider
    let wallet =
        LocalWallet::from_bytes(&hex::decode(wallet_private_key)?)?.with_chain_id(42161u64);
    let provider = Provider::<Http>::try_from(ARBITRUM_ONE_RPC_URL)?;
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));

    // Fetch operator min rates with early validation
    let min_rate = find_minimum_rate_instance(
        &selected_operator,
        &config.region,
        &config.instance_type,
        config.cpu,
        config.memory,
        &config.platform,
    ).context("Configuration not supported by operator")?;

    // Calculate costs
    let duration_seconds = (config.duration as u64) * 60;
    let (total_cost, total_rate) = calculate_total_cost(
        &min_rate,
        duration_seconds,
        config.bandwidth,
        &config.region,
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
    let metadata = create_metadata(
        &config.instance_type,
        &config.region,
        config.memory,
        config.cpu,
        &config.image_url,
        &config.job_name,
    );

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

    let ip_address = wait_for_ip_address(&url).await?;
    info!("IP address obtained: {}", ip_address);

    // First check basic connectivity
    if !ping_ip(&ip_address).await {
        return Err(anyhow!("Failed to establish TCP connection to the instance"));
    }
    info!("TCP connection established successfully");

    // Then check attestation
    if !check_attestation(&ip_address).await {
        return Err(anyhow!("Attestation check failed after maximum retries"));
    }

    info!("Enclave is ready! IP address: {}", ip_address);
    Ok(())
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
    let (buffered_gas, buffered_gas_price) = calculate_gas_parameters(estimated_gas, &client).await?;

    info!("Approving USDC spend...");
    let tx_call = approve_call
        .gas(buffered_gas)
        .gas_price(buffered_gas_price);
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

    info!("Creating job with gas price: {} wei", buffered_gas_price);
    info!(
        "Estimated gas cost: {} wei ({:.6} ETH)",
        buffered_gas,
        buffered_gas.as_u128() as f64 / 1e18
    );

    let tx_call = method_call.gas(buffered_gas).gas_price(buffered_gas_price);
    let pending_tx = tx_call.send().await?;

    info!("Job creation transaction: {:?}", pending_tx.tx_hash());

    let receipt = pending_tx
        .await?
        .context("No receipt found")?;

    // Add logging to check transaction status
    if !receipt.status.unwrap_or_default().is_zero() {
        info!("Transaction successful! Waiting 3 minutes for job initialization...");
        tokio::time::sleep(StdDuration::from_secs(180)).await;
    } else {
        return Err(anyhow!("Transaction failed - check contract interaction"));
    }

    // Calculate event signature hash
    let job_opened_signature = "JobOpened(bytes32,string,address,address,uint256,uint256,uint256)";
    let job_opened_topic = ethers::utils::keccak256(job_opened_signature.as_bytes());

    // Log all events for debugging
    info!("Transaction events:");
    for (idx, log) in receipt.logs.iter().enumerate() {
        info!("Log #{}", idx);
        info!("  Address: {:?}", log.address);
        info!("  Topics: {:?}", log.topics);
        info!("  Data: 0x{}", hex::encode(&log.data));
    }

    // Look for JobOpened event
    for log in receipt.logs.iter() {
        if log.topics[0] == H256::from_slice(&job_opened_topic) {
            info!("Found JobOpened event");
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
    let mut last_response = String::new();

    for attempt in 1..=IP_CHECK_RETRIES {
        info!("Checking for IP address (attempt {}/{})", attempt, IP_CHECK_RETRIES);
        
        let response = client.get(url).send().await?;
        let json: serde_json::Value = response.json().await?;
        last_response = json.to_string();
        
        info!("Response from refresh endpoint: {}", last_response);

        // Check both possible IP locations in response
        if let Some(ip) = json.get("job")
            .and_then(|job| job.get("ip"))
            .and_then(|ip| ip.as_str())
            .or_else(|| json.get("ip").and_then(|ip| ip.as_str()))
        {
            if !ip.is_empty() {
                info!("Found IP address: {}", ip);
                return Ok(ip.to_string());
            }
        }

        info!("IP not found yet, waiting {} seconds...", IP_CHECK_INTERVAL);
        tokio::time::sleep(StdDuration::from_secs(IP_CHECK_INTERVAL)).await;
    }

    Err(anyhow!(
        "IP address not found after {} attempts. Last response: {}",
        IP_CHECK_RETRIES,
        last_response
    ))
}

async fn ping_ip(ip: &str) -> bool {
    let address = format!("{}:1300", ip);
    for attempt in 1..=3 {
        info!("Attempting TCP connection to {} (attempt {}/3)", address, attempt);
        match tokio::time::timeout(StdDuration::from_secs(2), TcpStream::connect(&address)).await {
            Ok(Ok(_)) => {
                info!("TCP connection successful");
                return true;
            }
            Ok(Err(e)) => info!("TCP connection failed: {}", e),
            Err(_) => info!("TCP connection timed out"),
        }
        tokio::time::sleep(StdDuration::from_secs(2)).await;
    }
    info!("All TCP connection attempts failed");
    false
}

async fn check_attestation(ip: &str) -> bool {
    let client = reqwest::Client::new();
    let attestation_url = format!("http://{}:1300/attestation/raw", ip);

    for attempt in 1..=ATTESTATION_RETRIES {
        info!(
            "Checking attestation (attempt {}/{})",
            attempt, ATTESTATION_RETRIES
        );

        match client.get(&attestation_url).send().await {
            Ok(response) => {
                info!("Attestation status code: {}", response.status());
                if response.status().is_success() {
                    match response.bytes().await {
                        Ok(bytes) if !bytes.is_empty() => {
                            info!("Attestation check successful");
                            return true;
                        }
                        Ok(_) => info!("Empty attestation response"),
                        Err(e) => info!("Error reading attestation response: {}", e),
                    }
                }
            }
            Err(e) => info!("Failed to connect to attestation endpoint: {}", e),
        }

        info!("Waiting {} seconds before next attestation check...", ATTESTATION_INTERVAL);
        tokio::time::sleep(StdDuration::from_secs(ATTESTATION_INTERVAL)).await;
    }

    false
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
    // First find the rate card for the specified region
    let rate_card = operator.min_rates.iter().find(|rate_card| rate_card.region == region)
        .ok_or_else(|| anyhow!("No rate card found for region: {}", region))?;

    // Find matching instance rates
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

    if matching_rates.is_empty() {
        return Err(anyhow!(
            "No matching instance rate found for region: {}, instance: {}, vcpu: {}, memory: {}, arch: {}",
            region, instance, vcpu, memory, arch
        ));
    }

    // Find the minimum rate among matching instances
    Ok(matching_rates
        .into_iter()
        .min_by(|a, b| {
            let a_rate = U256::from_str_radix(a.min_rate.trim_start_matches("0x"), 16)
                .unwrap_or(U256::max_value());
            let b_rate = U256::from_str_radix(b.min_rate.trim_start_matches("0x"), 16)
                .unwrap_or(U256::max_value());
            a_rate.cmp(&b_rate)
        })
        .unwrap())
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

async fn calculate_gas_parameters(
    estimated_gas: U256,
    client: &SignerMiddleware<Provider<Http>, LocalWallet>,
) -> Result<(U256, U256)> {
    let buffered_gas = estimated_gas + (estimated_gas * 20 / 100);
    let gas_price = client.get_gas_price().await?;
    let buffered_gas_price = gas_price + (gas_price * 20 / 100);
    Ok((buffered_gas, buffered_gas_price))
}
