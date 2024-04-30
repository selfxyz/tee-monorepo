use anyhow::{Context, Error, Result};
use ethers::abi::{decode, ParamType, Token};
use ethers::prelude::*;
use ethers::utils::keccak256;
use log::{error, info};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::RwLock;
use tokio::time;

use crate::chain_util::get_block_number_by_timestamp;
use crate::constant::GATEWAY_BLOCK_STATES_TO_MAINTAIN;
use crate::contract_abi::CommonChainGatewayContract;
use crate::model::{CommonChainClient, GatewayData, Job};
use crate::HttpProvider;

// Initialize the gateway epoch state
pub async fn gateway_epoch_state_service(
    current_time: u64,
    provider: &Arc<HttpProvider>,
    common_chain_client: Arc<CommonChainClient>,
    tx: Sender<(Job, Arc<CommonChainClient>)>,
) {
    let current_cycle = (current_time - common_chain_client.epoch) / common_chain_client.time_interval;
    let initial_epoch_cycle: u64;
    if current_cycle >= GATEWAY_BLOCK_STATES_TO_MAINTAIN {
        initial_epoch_cycle = current_cycle - GATEWAY_BLOCK_STATES_TO_MAINTAIN + 1;
    } else {
        initial_epoch_cycle = 1;
    };
    {
        let contract_address_clone = common_chain_client.gateway_contract_addr.clone();
        let provider_clone = provider.clone();
        let com_chain_gateway_contract_clone = common_chain_client.gateway_contract.clone();
        let gateway_epoch_state_clone = Arc::clone(&common_chain_client.gateway_epoch_state);

        let mut cycle_number = initial_epoch_cycle;
        while cycle_number <= current_cycle {
            let _current_cycle = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
                - common_chain_client.epoch)
                / common_chain_client.time_interval;

            if _current_cycle - cycle_number >= GATEWAY_BLOCK_STATES_TO_MAINTAIN {
                cycle_number += 1;
                continue;
            }

            let success = generate_gateway_epoch_state_for_cycle(
                contract_address_clone,
                &provider_clone,
                com_chain_gateway_contract_clone.clone(),
                &gateway_epoch_state_clone,
                cycle_number,
                common_chain_client.epoch,
                common_chain_client.time_interval,
            )
            .await;

            if success.is_err() {
                error!(
                    "Failed to generate gateway epoch state for cycle {} - Error: {:?}",
                    cycle_number, success
                );
                continue;
            }
            {
                let mut waitlist_handle = common_chain_client.gateway_epoch_state_waitlist.write().unwrap();
                if let Some(job_list) = waitlist_handle.remove(&cycle_number) {
                    let common_chain_client_clone = common_chain_client.clone();
                    let tx_clone = tx.clone();
                    tokio::spawn(async move {
                        for job in job_list {
                            let _ = common_chain_client_clone.clone().job_placed_handler(job, tx_clone.clone()).await; //TODO check return value
                        }
                    });
                }
            }
            cycle_number += 1;
        }
    }

    let mut cycle_number = current_cycle + 1;
    let last_cycle_timestamp = common_chain_client.epoch + (current_cycle * common_chain_client.time_interval);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let until_epoch = Duration::from_secs(last_cycle_timestamp + common_chain_client.time_interval);

    if until_epoch > now {
        let sleep_duration = until_epoch - now;
        tokio::time::sleep(sleep_duration).await;
    }

    let mut interval = time::interval(Duration::from_secs(common_chain_client.time_interval));

    loop {
        interval.tick().await;

        loop {
            let current_cycle = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
                - common_chain_client.epoch)
                / common_chain_client.time_interval;

            if current_cycle - cycle_number >= GATEWAY_BLOCK_STATES_TO_MAINTAIN {
                cycle_number += 1;
                continue;
            }

            let success = generate_gateway_epoch_state_for_cycle(
                common_chain_client.gateway_contract_addr.clone(),
                &provider.clone(),
                common_chain_client.gateway_contract.clone(),
                &common_chain_client.gateway_epoch_state,
                cycle_number,
                common_chain_client.epoch,
                common_chain_client.time_interval,
            )
            .await;

            if success.is_err() {
                error!(
                    "Failed to generate gateway epoch state for cycle {} - Error: {:?}",
                    cycle_number,
                    success.err().unwrap()
                );
                continue;
            }
            {
                let mut waitlist_handle = common_chain_client.gateway_epoch_state_waitlist.write().unwrap();
                if let Some(job_list) = waitlist_handle.remove(&cycle_number) {
                    let common_chain_client_clone = common_chain_client.clone();
                    let tx_clone = tx.clone();
                    tokio::spawn(async move {
                        for job in job_list {
                            let _ = common_chain_client_clone.clone().job_placed_handler(job, tx_clone.clone()).await; //TODO check return value
                        }
                    });
                }
            }
            break;
        }
        // veegee
        prune_old_cycle_states(&common_chain_client.gateway_epoch_state, common_chain_client.epoch, common_chain_client.time_interval).await;

        cycle_number += 1;
    }
}

pub async fn generate_gateway_epoch_state_for_cycle(
    contract_address: Address,
    provider: &Arc<HttpProvider>,
    com_chain_gateway_contract: CommonChainGatewayContract<HttpProvider>,
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    cycle_number: u64,
    epoch: u64,
    time_interval: u64,
) -> Result<(), Error> {
    // last added cycle will be the cycle number which is less than the current cycle number
    // since this fn is run via spawn,
    // it is possible that a greater or equal cycle number is already added
    let mut last_added_cycle: Option<u64> = None;
    let added_cycles: Vec<u64>;
    // scope for the read lock
    {
        let gateway_epoch_state_guard = gateway_epoch_state.read().unwrap();
        added_cycles = gateway_epoch_state_guard.keys().cloned().collect();
    }
    for cycle in added_cycles.iter().rev() {
        if *cycle < cycle_number {
            last_added_cycle = Some(cycle.clone());
            break;
        }
    }
    drop(added_cycles);

    let from_block_number: u64;

    if last_added_cycle.is_none() {
        from_block_number = 0;
    } else {
        // scope for the read lock
        {
            // get last added cycle's block number
            let gateway_cycle_map = gateway_epoch_state
                .read()
                .unwrap()
                .get(&last_added_cycle.unwrap())
                .unwrap()
                .clone();

            if gateway_cycle_map.is_empty() {
                from_block_number = 0;
            } else {
                from_block_number =
                    gateway_cycle_map.values().next().unwrap().last_block_number + 1;
            }
        }
    }

    let timestamp_to_fetch = epoch + (cycle_number * time_interval);

    // to_block_number can be less than from_block_number
    // in case of no blocks created in this epoch cycle
    let mut to_block_number = get_block_number_by_timestamp(&provider, timestamp_to_fetch).await;

    if to_block_number.is_none() {
        error!(
            "Failed to get block number for timestamp {}",
            timestamp_to_fetch
        );
        to_block_number = Some(from_block_number);
    }

    let to_block_number = to_block_number.unwrap();

    // initialize the gateway epoch state[current_cycle] with empty map if it doesn't exist
    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        gateway_epoch_state_guard
            .entry(cycle_number)
            .or_insert(BTreeMap::new());
    }
    if last_added_cycle.is_some() {
        // initialize the gateway epoch state[current_cycle] with the previous cycle state
        let mut last_cycle_state_map: BTreeMap<Address, GatewayData>;
        // scope for the read lock
        {
            last_cycle_state_map = gateway_epoch_state
                .read()
                .unwrap()
                .get(&last_added_cycle.unwrap())
                .unwrap()
                .clone();
        }
        // update the last block number of the gateway data
        for (_, gateway_data) in last_cycle_state_map.iter_mut() {
            gateway_data.last_block_number = to_block_number;
        }

        // scope for the write lock
        {
            let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
            gateway_epoch_state_guard.insert(cycle_number, last_cycle_state_map);
        }

        // In case where to_block_number < from_block_number, return here
        // This will happen in the case when no blocks were created in this epoch cycle,
        // so the state remains the same as the previous state
        if to_block_number < from_block_number {
            return Ok(());
        }
    }

    if from_block_number == 0 && to_block_number == 0 {
        return Ok(()); // no blocks to process
    }

    // events are only used to update the gateway state and req_chain_ids, not the stake amount
    let event_filter = Filter::new()
        .address(contract_address)
        .from_block(from_block_number)
        .to_block(to_block_number)
        .topic0(vec![
            keccak256("GatewayRegistered(address,address,uint256[])"),
            keccak256("GatewayDeregistered(address)"),
            keccak256("ChainAdded(address,uint256)"),
            keccak256("ChainRemoved(address,uint256)"),
        ]);

    let logs = provider
        .get_logs(&event_filter)
        .await
        .context("Failed to get logs for the gateway contract")
        .unwrap();

    for log in logs {
        let topics = log.topics.clone();

        if topics[0] == keccak256("GatewayRegistered(address,address,uint256[])").into() {
            process_gateway_registered_event(
                log,
                cycle_number,
                to_block_number,
                &gateway_epoch_state,
            )
            .await;
        } else if topics[0] == keccak256("GatewayDeregistered(address)").into() {
            process_gateway_deregistered_event(log, to_block_number, &gateway_epoch_state).await;
        } else if topics[0] == keccak256("ChainAdded(address,uint256)").into() {
            process_chain_added_event(log, cycle_number, &gateway_epoch_state).await;
        } else if topics[0] == keccak256("ChainRemoved(address,uint256)").into() {
            process_chain_removed_event(log, cycle_number, &gateway_epoch_state).await;
        }
    }

    // fetch the gateways mapping for the updated stakes.
    let gateway_addresses: Vec<Address>;
    // scope for the read lock
    {
        gateway_addresses = gateway_epoch_state
            .read()
            .unwrap()
            .get(&cycle_number)
            .unwrap()
            .keys()
            .cloned()
            .collect();
    }

    for address in gateway_addresses {
        let (_, stake_amount, _, _) = com_chain_gateway_contract
            .gateways(address)
            .block(BlockId::from(to_block_number))
            .call()
            .await
            .context("Failed to get gateway data")?;

        // scope for the write lock
        {
            let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
            gateway_epoch_state_guard
                .get_mut(&cycle_number)
                .unwrap()
                .get_mut(&address)
                .unwrap()
                .stake_amount = stake_amount;
        }
    }

    info!("Generated gateway epoch state for cycle {}", cycle_number);
    Ok(())
}

async fn prune_old_cycle_states(
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    epoch: u64,
    time_interval: u64,
) {
    let current_cycle = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        - epoch)
        / time_interval;
    let mut cycles_to_remove = vec![];

    // scope for the read lock
    {
        let gateway_epoch_state_guard = gateway_epoch_state.read().unwrap();
        for cycle in gateway_epoch_state_guard.keys() {
            // if a state is older than 1.5 times the number of states to maintain, remove it
            // chosen a number larger than the number to maintain because in some cases, of delay,
            // an older state might be used to read and initialize the current state
            if current_cycle - cycle >= (GATEWAY_BLOCK_STATES_TO_MAINTAIN * 3 / 2) {
                cycles_to_remove.push(cycle.clone());
            } else {
                break;
            }
        }
    }
    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        for cycle in cycles_to_remove {
            gateway_epoch_state_guard.remove(&cycle);
        }
    }
}

async fn process_gateway_registered_event(
    log: Log,
    cycle: u64,
    to_block_number: u64,
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
) {
    let address = Address::from_slice(log.topics[1][12..].try_into().unwrap());

    let decoded = decode(
        &vec![ParamType::Array(Box::new(ParamType::Uint(256)))],
        &log.data.0,
    );

    if decoded.is_err() {
        error!(
            "Failed to decode gateway registered event {}",
            decoded.err().unwrap()
        );
        return;
    }

    let decoded = decoded.unwrap();

    let mut req_chain_ids = BTreeSet::new();

    if let Token::Array(array_tokens) = decoded[0].clone() {
        for token in array_tokens {
            if let Token::Uint(req_chain_id) = token {
                req_chain_ids.insert(U256::from(req_chain_id).as_u64());
            }
        }
    }

    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        if let Some(cycle_gateway_state) = gateway_epoch_state_guard.get_mut(&cycle) {
            cycle_gateway_state.insert(
                address.clone(),
                GatewayData {
                    last_block_number: to_block_number,
                    address,
                    stake_amount: U256::zero(), // gateways call is used to get the stake amount
                    status: true,
                    req_chain_ids,
                },
            );
        }
    }
}

async fn process_gateway_deregistered_event(
    log: Log,
    cycle: u64,
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
) {
    let address = Address::from_slice(log.topics[1][12..].try_into().unwrap());

    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        if let Some(cycle_gateway_state) = gateway_epoch_state_guard.get_mut(&cycle) {
            cycle_gateway_state.remove(&address);
        }
    }
}

async fn process_chain_added_event(
    log: Log,
    cycle: u64,
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
) {
    let address = Address::from_slice(log.topics[1][12..].try_into().unwrap());

    let decoded = decode(&vec![ParamType::Uint(256)], &log.data.0);

    if decoded.is_err() {
        error!(
            "Failed to decode gateway registered event {}",
            decoded.err().unwrap()
        );
        return;
    }

    let decoded = decoded.unwrap();
    let chain_id = decoded[0].clone().into_uint().unwrap().as_u64();

    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        if let Some(cycle_gateway_state) = gateway_epoch_state_guard.get_mut(&cycle) {
            if let Some(gateway_data) = cycle_gateway_state.get_mut(&address) {
                gateway_data.req_chain_ids.insert(chain_id);
            }
        }
    }
}

async fn process_chain_removed_event(
    log: Log,
    cycle: u64,
    gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
) {
    let address = Address::from_slice(log.topics[1][12..].try_into().unwrap());

    let decoded = decode(&vec![ParamType::Uint(256)], &log.data.0);

    if decoded.is_err() {
        error!(
            "Failed to decode gateway registered event {}",
            decoded.err().unwrap()
        );
        return;
    }

    let decoded = decoded.unwrap();
    let chain_id = decoded[0].clone().into_uint().unwrap().as_u64();

    // scope for the write lock
    {
        let mut gateway_epoch_state_guard = gateway_epoch_state.write().unwrap();
        if let Some(cycle_gateway_state) = gateway_epoch_state_guard.get_mut(&cycle) {
            if let Some(gateway_data) = cycle_gateway_state.get_mut(&address) {
                gateway_data.req_chain_ids.remove(&chain_id);
            }
        }
    }
}
