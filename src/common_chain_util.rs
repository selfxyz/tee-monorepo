use std::collections::BTreeMap; // For time-based ordered map
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub struct BlockData {
    pub number: u64,
    pub timestamp: u64,
}

pub async fn prune_old_blocks(recent_blocks: &Arc<RwLock<BTreeMap<u64, BlockData>>>) {
    // Define the cutoff time
    let oldest_valid_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        - 120; // 2 minutes data retention

    // Remove entries older than the cutoff time
    recent_blocks
        .write()
        .await
        .retain(|timestamp, _| timestamp > &oldest_valid_timestamp);
}

pub async fn get_next_block_number(
    recent_blocks: &Arc<RwLock<BTreeMap<u64, BlockData>>>,
    timestamp: u64,
) -> Option<u64> {
    let recent_blocks = recent_blocks.read().await;
    let mut block_number: Option<u64> = None;
    while block_number.is_none() {
        for (&_block_timestamp, block_data) in recent_blocks.range((
            std::ops::Bound::Excluded(timestamp),
            std::ops::Bound::Unbounded,
        )) {
            block_number = Some(block_data.number);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    return block_number;
}
