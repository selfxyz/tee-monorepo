use crate::types::Platform;
use anyhow::{anyhow, Result};
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, U256, H256};
use ethers::contract::abigen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::info;

const OPERATOR_LIST_URL: &str = "https://sk.arb1.marlin.org/operators/spec/ArbOne";
const ARBITRUM_SEPOLIA_RPC_URL: &str = "https://arbitrum-sepolia.blockpi.network/v1/rpc/public";
const OYSTER_MARKET_ADDRESS: &str = "0x9d95D61eA056721E358BC49fE995caBF3B86A34B";
const USDC_ADDRESS: &str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
const JOB_REFRESH_ENDPOINT: &str = "https://sk.arb1.marlin.org/operators/jobs/refresh/ArbOne/";

// Generate type-safe contract bindings
abigen!(
    ChainlinkPriceFeed,
    "./src/abis/chainlink_abi.json",
    event_derives(serde::Serialize, serde::Deserialize)
);

abigen!(
    USDC,
    "./src/abis/token_abi.json",
    event_derives(serde::Serialize, serde::Deserialize)
);

abigen!(
    OysterMarket,
    "./src/abis/oyster_market_abi.json",
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
    duration: u32,
    max_usd_per_hour: f64,
    image_url: &str,
    platform: Platform,
    region: &str,
    wallet_private_key: &str,
    operator: Option<&str>,
) -> Result<()> {
    info!("Fetching available operators...");
    let operators = fetch_operators(OPERATOR_LIST_URL).await?;

    // Filter operators based on requirements
    let matching_operators: Vec<_> = operators
        .iter()
        .filter(|(_, op)| {
            op.allowed_regions.contains(&region.to_string())
                && op.min_rates.iter().any(|rate_card| {
                    rate_card.region == region
                        && rate_card.rate_cards.iter().any(|instance| {
                            instance.cpu == cpu
                                && instance.memory == memory
                                && instance.arch == platform.as_str()
                        })
                })
        })
        .collect();

    if matching_operators.is_empty() {
        return Err(anyhow!("No matching operators found for the given requirements"));
    }

    // If operator is specified, verify it's in the matching list
    let selected_operator = if let Some(op_addr) = operator {
        matching_operators
            .iter()
            .find(|(addr, _)| addr == &op_addr)
            .ok_or_else(|| anyhow!("Specified operator does not match requirements"))?
    } else {
        // Select the operator with the lowest rate
        matching_operators
            .iter()
            .min_by_key(|(_, op)| {
                op.min_rates
                    .iter()
                    .find(|rc| rc.region == region)
                    .and_then(|rc| {
                        rc.rate_cards
                            .iter()
                            .find(|ir| ir.cpu == cpu && ir.memory == memory)
                            .map(|ir| U256::from_str_radix(&ir.min_rate[2..], 16).unwrap_or_default())
                    })
                    .unwrap_or_default()
            })
            .ok_or_else(|| anyhow!("Failed to find operator with lowest rate"))?
    };

    let rate_card = selected_operator
        .1
        .min_rates
        .iter()
        .find(|rc| rc.region == region)
        .ok_or_else(|| anyhow!("No rate card found for region"))?;

    let instance_rate = rate_card
        .rate_cards
        .iter()
        .find(|ir| ir.cpu == cpu && ir.memory == memory)
        .ok_or_else(|| anyhow!("No matching instance rate found"))?;

    // Convert rate to USD and verify against max_usd_per_hour
    let rate_eth = U256::from_str_radix(&instance_rate.min_rate[2..], 16)?;
    let rate_usd = convert_eth_to_usd(rate_eth).await?;
    if rate_usd > max_usd_per_hour {
        return Err(anyhow!(
            "Instance rate ${:.2} exceeds maximum USD per hour ${:.2}",
            rate_usd,
            max_usd_per_hour
        ));
    }

    info!("Selected operator: {}", selected_operator.0);
    info!("Hourly rate: ${:.2}", rate_usd);

    // Setup wallet and provider
    let wallet: LocalWallet = wallet_private_key.parse::<LocalWallet>()?.with_chain_id(421614u64);
    let provider = Provider::<Http>::try_from(ARBITRUM_SEPOLIA_RPC_URL)?;
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    // Create metadata
    let metadata = create_metadata(
        &instance_rate.instance,
        region,
        memory,
        cpu,
        image_url,
        "oyster_job",
    );

    // Calculate total cost
    let duration_hours = duration * 24;
    let total_cost = rate_eth
        .checked_mul(U256::from(duration_hours))
        .ok_or_else(|| anyhow!("Total cost calculation overflow"))?;

    // Approve USDC
    approve_usdc(total_cost, client.clone()).await?;

    // Create job
    let job_id = create_new_oyster_job(
        metadata,
        selected_operator.0.parse()?,
        rate_eth,
        total_cost,
        client.clone(),
    )
    .await?;

    info!("Job created with ID: {:?}", job_id);

    // Wait for IP address
    let url = format!("{}{:?}", JOB_REFRESH_ENDPOINT, job_id);
    info!("Waiting for enclave to start...");

    loop {
        let ip_address = wait_for_ip_address(&url).await?;
        if ping_ip(&ip_address).await {
            if check_attestation(&ip_address).await {
                info!("Enclave is ready! IP address: {}", ip_address);
                break;
            }
            info!("Waiting for attestation...");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    Ok(())
}

async fn fetch_operators(url: &str) -> Result<Vec<(String, Operator)>> {
    let client = reqwest::Client::new();
    
    info!("Requesting operators from URL: {}", url);
    let response = client.get(url).send().await.map_err(|e| {
        anyhow::anyhow!("Failed to fetch operators: {}", e)
    })?;

    let status = response.status();
    info!("Response status: {}", status);

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Error fetching operators. Status: {} Body: {}",
            status,
            body
        ));
    }

    let body = response.text().await.map_err(|e| {
        anyhow::anyhow!("Failed to get response body: {}", e)
    })?;

    info!("Response body: {}", body);

    let operators_map: HashMap<String, Operator> = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!("Failed to parse JSON: {}", e)
    })?;

    Ok(operators_map.into_iter().collect())
}

async fn convert_eth_to_usd(amount_eth: U256) -> Result<f64> {
    let provider = Arc::new(Provider::<Http>::try_from("https://arb1.arbitrum.io/rpc")?);
    let price_feed_address = "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612"
        .parse::<Address>()
        .unwrap();
    let price_feed = ChainlinkPriceFeed::new(price_feed_address, provider.clone());
    let price_feed = Arc::new(price_feed);

    let (_, price, _, _, _) = price_feed.latest_round_data().call().await?;

    let price_usd = U256::try_from(price.abs())?;
    let amount_usd = amount_eth
        .checked_mul(price_usd)
        .ok_or_else(|| anyhow!("USD conversion overflow"))?
        / U256::exp10(8);

    Ok(amount_usd.as_u128() as f64 / 1e18)
}

async fn approve_usdc(
    amount: U256,
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<()> {
    let usdc_address = USDC_ADDRESS.parse::<Address>()?;
    let usdc = USDC::new(usdc_address, client.clone());
    let usdc = Arc::new(usdc);

    let market_address = OYSTER_MARKET_ADDRESS.parse::<Address>()?;
    // Create an approve call before sending, so its value isn't dropped too early
    let approve_call = usdc.approve(market_address, amount);
    let tx = approve_call.send().await?;

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
    let market = OysterMarket::new(market_address, client.clone());
    let market = Arc::new(market);

    // Create the transaction call first to extend its lifetime
    let job_open_call = market.job_open(metadata, provider, rate, balance);
    let tx = job_open_call.send().await?;
    info!("Job creation transaction: {:?}", tx.tx_hash());

    let receipt = tx.await?.ok_or_else(|| anyhow!("No receipt found"))?;
    let job_opened_event = receipt
        .logs
        .iter()
        .find(|log| {
            log.topics[0]
                == H256::from_slice(&ethers::utils::keccak256(
                    "JobOpened(bytes32,string,address,address,uint256,uint256,uint256)",
                ))
        })
        .ok_or_else(|| anyhow!("JobOpened event not found"))?;

    Ok(job_opened_event.topics[1])
}

async fn wait_for_ip_address(url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let json: serde_json::Value = response.json().await?;
    json["ip"]
        .as_str()
        .ok_or_else(|| anyhow!("IP address not found in response"))
        .map(String::from)
}

async fn ping_ip(ip: &str) -> bool {
    let address = format!("{}:1300", ip);
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&address)).await {
            Ok(Ok(_)) => return true,
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
    false
}

async fn check_attestation(ip: &str) -> bool {
    let url = format!("http://{}:1300/attestation/raw", ip);
    let client = reqwest::Client::new();
    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(bytes) = response.bytes().await {
                    return !bytes.is_empty();
                }
            }
        }
        Err(_) => {}
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
