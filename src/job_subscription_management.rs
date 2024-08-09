use std::{
    collections::{BinaryHeap, HashMap},
    error::Error,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use tokio::{
    sync::mpsc::channel,
    time::{sleep_until, Instant},
};

use crate::model::{
    JobSubscriptionAction, JobSubscriptionChannelType, JobSubscriptionManagement, SubscriptionHeap,
    SubscriptionJob,
};

fn unix_timestamp_to_instant(timestamp: u64) -> Instant {
    let duration = Duration::from_secs(timestamp);
    let system_time = UNIX_EPOCH + duration;
    Instant::now()
        + system_time
            .duration_since(SystemTime::now())
            .unwrap_or_default()
}

impl PartialEq for SubscriptionHeap {
    fn eq(&self, other: &Self) -> bool {
        self.next_trigger_time == other.next_trigger_time
    }
}

impl Eq for SubscriptionHeap {}

impl PartialOrd for SubscriptionHeap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.next_trigger_time
                .cmp(&other.next_trigger_time)
                .reverse(),
        )
    }
}

impl Ord for SubscriptionHeap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.next_trigger_time
            .cmp(&other.next_trigger_time)
            .reverse()
    }
}

impl JobSubscriptionManagement {
    pub async fn new() -> Self {
        let subscription_heap = BinaryHeap::new();
        let subscription_jobs = HashMap::new();

        let (tx, rx) = channel::<JobSubscriptionChannelType>(100);

        Self {
            subscription_heap: Arc::new(RwLock::new(subscription_heap)),
            subscription_jobs: Arc::new(RwLock::new(subscription_jobs)),
            tx: Arc::new(RwLock::new(tx)),
            rx: Arc::new(RwLock::new(rx)),
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        self.handle_job_subscription_management().await;
        Ok(())
    }

    pub async fn handle_job_subscription_management(self: Arc<Self>) {
        let mut rx = self.rx.write().unwrap();
        loop {
            let next_trigger = {
                self.subscription_heap
                    .read()
                    .unwrap()
                    .peek()
                    .map(|sub| sub.next_trigger_time)
            };

            tokio::select! {
                Some(job_subscription_channel_type) = rx.recv() => {
                    match job_subscription_channel_type.subscription_action {
                        JobSubscriptionAction::Add => {
                            self.add_subscription_job(job_subscription_channel_type.subscription_job).await;
                        }
                        JobSubscriptionAction::Remove => {
                            // self.remove_subscription_job(job_subscription_channel_type.subscription_job).await;
                        }
                        JobSubscriptionAction::ParamsUpdate => {
                            // self.update_subscription_job(job_subscription_channel_type.subscription_job).await;
                        }
                        JobSubscriptionAction::TerminationParamsUpdate => {
                            // self.update_subscription_job_termination_params(job_subscription_channel_type.subscription_job).await;
                        }
                    }
                }
                _ = sleep_until(next_trigger.map(|t| unix_timestamp_to_instant(t)).unwrap_or_else(Instant::now)), if next_trigger.is_some() => {
                    println!("Triggering subscription job");
                }
            }
        }
    }

    pub async fn add_subscription_job(self: &Arc<Self>, subscription_job: SubscriptionJob) {
        let mut subscription_jobs = self.subscription_jobs.write().unwrap();
        self.add_next_trigger_time_to_heap(subscription_job.clone())
            .await;
        subscription_jobs.insert(subscription_job.subscription_id, subscription_job.clone());
    }

    pub async fn add_next_trigger_time_to_heap(
        self: &Arc<Self>,
        subscription_job: SubscriptionJob,
    ) {
        let mut subscription_heap = self.subscription_heap.write().unwrap();

        let mut next_trigger_time =
            (subscription_job.starttime + subscription_job.interval).as_u64();
        if next_trigger_time > subscription_job.termination_time.as_u64() {
            return;
        }
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // if the next trigger time is in the past, we need to find the next trigger time
        while next_trigger_time < current_time {
            next_trigger_time += subscription_job.interval.as_u64();
        }
        subscription_heap.push(SubscriptionHeap {
            subscription_id: subscription_job.subscription_id,
            next_trigger_time,
        });
    }
}
