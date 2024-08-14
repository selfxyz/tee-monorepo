use ethers::{
    abi::{decode, ParamType},
    types::{BigEndianHash, Log, U256},
};
use log::{error, info};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::{sleep_until, Instant},
};

use crate::{
    error::ServerlessError,
    model::{
        ContractsClient, GatewayJobType, Job, JobSubscriptionAction, JobSubscriptionChannelType,
        SubscriptionJob, SubscriptionJobHeap,
    },
};

fn unix_timestamp_to_instant(timestamp: u64) -> Instant {
    let duration = Duration::from_secs(timestamp);
    let system_time = UNIX_EPOCH + duration;
    Instant::now()
        + system_time
            .duration_since(SystemTime::now())
            .unwrap_or_default()
}

impl PartialEq for SubscriptionJobHeap {
    fn eq(&self, other: &Self) -> bool {
        self.next_trigger_time == other.next_trigger_time
    }
}

impl Eq for SubscriptionJobHeap {}

impl PartialOrd for SubscriptionJobHeap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.next_trigger_time
                .cmp(&other.next_trigger_time)
                .reverse(),
        )
    }
}

impl Ord for SubscriptionJobHeap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.next_trigger_time
            .cmp(&other.next_trigger_time)
            .reverse()
    }
}

pub async fn job_subscription_management(
    contracts_client: Arc<ContractsClient>,
    mut rx: Receiver<JobSubscriptionChannelType>,
    req_chain_tx: Sender<Job>,
) {
    loop {
        let next_trigger_time: Option<u64>;
        // Scope for read lock on subscription_job_heap
        {
            let subscription_heap_guard = contracts_client.subscription_job_heap.read().unwrap();
            next_trigger_time = subscription_heap_guard.peek().map(|t| t.next_trigger_time);
        }

        tokio::select! {
            Some(job_subscription_channel_data) = rx.recv() => {
                match job_subscription_channel_data.subscription_action {
                    JobSubscriptionAction::Add => {
                        info!(
                            "Adding new subscription JobSubscriptionId: {}",
                            job_subscription_channel_data.subscription_log.topics[1]
                        );
                        let contracts_client_clone = contracts_client.clone();
                        tokio::spawn(async move {
                            let _ = add_subscription_job(
                                &contracts_client_clone,
                                job_subscription_channel_data.subscription_log,
                                job_subscription_channel_data.request_chain_id
                            ).await;
                        });
                    }
                    JobSubscriptionAction::Remove => {
                        // remove_subscription_job(job_subscription_channel_data.subscription_job).await;
                    }
                    JobSubscriptionAction::ParamsUpdate => {
                        // update_subscription_job(job_subscription_channel_data.subscription_job).await;
                    }
                    JobSubscriptionAction::TerminationParamsUpdate => {
                        // update_subscription_job_termination_params(job_subscription_channel_data.subscription_job).await;
                    }
                }
            }
            _ = sleep_until(next_trigger_time.map(|t|
                unix_timestamp_to_instant(t)
            ).unwrap_or_else(Instant::now)), if next_trigger_time.is_some() => {
                let contracts_client_clone = contracts_client.clone();
                let subscription: Option<SubscriptionJobHeap>;
                {
                    let mut subscription_job_heap = contracts_client.subscription_job_heap
                        .write()
                        .unwrap();
                    subscription = subscription_job_heap.pop();
                }

                if subscription.is_none() {
                    error!("Subscription Job Triggered but no subscription found");
                    continue;
                }
                let subscription = subscription.unwrap();

                let req_chain_tx_clone = req_chain_tx.clone();
                let subscription_clone = subscription.clone();
                tokio::spawn(async move {
                    trigger_subscription_job(subscription_clone, contracts_client_clone, req_chain_tx_clone).await;
                });
                add_next_trigger_time_to_heap(
                    &contracts_client,
                    subscription.subscription_id.clone(),
                    Some(subscription.next_trigger_time)
                ).await;
            }
            else => {
                info!("Awaiting");
                // do nothing
            }
        }
    }
}

async fn add_subscription_job(
    contracts_client: &Arc<ContractsClient>,
    subscription_log: Log,
    request_chain_id: u64,
) -> Result<(), ServerlessError> {
    let types = vec![
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Address,
        ParamType::FixedBytes(32),
        ParamType::Bytes,
        ParamType::Uint(256),
    ];

    let decoded = decode(&types, &subscription_log.data.0);
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(e) => {
            error!("Failed to decode subscription log: {}", e);
            return Err(ServerlessError::LogDecodeFailure);
        }
    };

    let subscription_job = SubscriptionJob {
        subscription_id: subscription_log.topics[1].into_uint(),
        request_chain_id,
        subscriber: subscription_log.topics[2].into(),
        interval: decoded[0].clone().into_uint().unwrap().into(),
        termination_time: decoded[2].clone().into_uint().unwrap().into(),
        user_timeout: decoded[3].clone().into_uint().unwrap().into(),
        tx_hash: decoded[5].clone().into_fixed_bytes().unwrap(),
        code_input: decoded[6].clone().into_bytes().unwrap().into(),
        starttime: decoded[7].clone().into_uint().unwrap().into(),
    };

    {
        let mut subscription_jobs = contracts_client.subscription_jobs.write().unwrap();
        subscription_jobs.insert(subscription_job.subscription_id, subscription_job.clone());
    }

    add_next_trigger_time_to_heap(&contracts_client, subscription_job.subscription_id, None).await;
    Ok(())
}

async fn add_next_trigger_time_to_heap(
    contracts_client: &Arc<ContractsClient>,
    subscription_id: U256,
    previous_trigger_time: Option<u64>,
) {
    let subscription_job: SubscriptionJob = contracts_client
        .subscription_jobs
        .read()
        .unwrap()
        .get(&subscription_id)
        .cloned()
        .unwrap();

    let mut next_trigger_time = {
        if previous_trigger_time.is_some() {
            previous_trigger_time.unwrap() + subscription_job.interval.as_u64()
        } else {
            (subscription_job.starttime + subscription_job.interval).as_u64()
        }
    };

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // if the next trigger time is in the past, we need to find the next trigger time
    if next_trigger_time <= current_time {
        let how_many_intervals =
            (current_time - next_trigger_time) / subscription_job.interval.as_u64();
        next_trigger_time += (how_many_intervals + 1) * subscription_job.interval.as_u64();
    }

    if next_trigger_time > subscription_job.termination_time.as_u64() {
        info!(
            "Subscription Job has reached termination time - Subscription ID: {}",
            subscription_job.subscription_id
        );
        return;
    }
    {
        let mut subscription_job_heap = contracts_client.subscription_job_heap.write().unwrap();
        subscription_job_heap.push(SubscriptionJobHeap {
            subscription_id: subscription_job.subscription_id,
            next_trigger_time,
        });
    }
}

async fn trigger_subscription_job(
    subscription: SubscriptionJobHeap,
    contracts_client: Arc<ContractsClient>,
    req_chain_tx: Sender<Job>,
) {
    info!(
        "Triggering subscription job with ID: {}",
        subscription.subscription_id
    );

    let subscription_job: Option<SubscriptionJob>;
    {
        let subscription_jobs_guard = contracts_client.subscription_jobs.read().unwrap();
        subscription_job = subscription_jobs_guard
            .get(&subscription.subscription_id)
            .cloned();
    }

    if subscription_job.is_none() {
        info!(
            "Job No longer active for Subscription - Subscription ID: {}",
            subscription.subscription_id
        );
        return;
    }

    let subscription_job = subscription_job.unwrap();

    let job = subscription_job_to_relay_job(subscription_job, subscription.next_trigger_time).await;

    contracts_client
        .job_relayed_handler(job, req_chain_tx)
        .await;
}

async fn subscription_job_to_relay_job(
    subscription_job: SubscriptionJob,
    trigger_timestamp: u64,
) -> Job {
    let instance_count =
        (U256::from(trigger_timestamp) - subscription_job.starttime) / subscription_job.interval;
    let job_id = subscription_job.subscription_id + instance_count;
    let instance_starttime =
        subscription_job.starttime + instance_count * subscription_job.interval;

    Job {
        job_id,
        request_chain_id: subscription_job.request_chain_id,
        tx_hash: subscription_job.tx_hash,
        code_input: subscription_job.code_input,
        user_timeout: subscription_job.user_timeout,
        starttime: instance_starttime,
        job_owner: subscription_job.subscriber,
        job_type: GatewayJobType::JobRelay,
        sequence_number: 1,
        gateway_address: None,
    }
}
