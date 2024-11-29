use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use actix_web::web::Data;
use ethers::types::U256;
use tokio::sync::mpsc::Sender;
use tokio::time::interval;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::utils::{check_and_delete_file, AppState, SecretMetadata, SecretsTxnMetadata};

// TODO: Add support for marking secret stores dead based on absence of alive acknowledgement under a timeout
// Periodic job for monitoring stored secrets, sending alive acknowledgement and deleting those past their end timestamp
pub async fn secrets_monitor_and_garbage_cleaner(
    app_state: Data<AppState>,
    tx: Sender<SecretsTxnMetadata>,
) {
    // Start the periodic job with interval 'MARK_ALIVE_TIMEOUT/2'
    let mut interval = interval(Duration::from_secs(app_state.mark_alive_timeout - 2));

    loop {
        interval.tick().await; // Wait for the next tick

        // If enclave is deregistered, stop the job because acknowledgments won't be accepted then
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }

        // Send txn response with the mark alive counterpart
        let _ = Retry::spawn(
            ExponentialBackoff::from_millis(5).map(jitter).take(3),
            || async {
                tx.send(SecretsTxnMetadata::MarkStoreAlive(
                    SystemTime::now() + Duration::from_secs(2),
                ))
                .await
            },
        )
        .await;

        // Clone and get the data of secrets stored inside the enclave at the moment
        let secrets_stored: Vec<(U256, SecretMetadata)> = app_state
            .secrets_stored
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, secret)| (id, secret.clone()))
            .collect();

        for (secret_id, secret_stored_metadata) in secrets_stored {
            // If the secret ID has passed its end timestamp, remove it from the storage
            if SystemTime::now()
                > SystemTime::UNIX_EPOCH
                    + Duration::from_secs(secret_stored_metadata.end_timestamp.as_u64())
            {
                let _ = app_state.secrets_stored.lock().unwrap().remove(&secret_id);

                // Remove the secret stored in the filesystem
                let secret_store_path = app_state.secret_store_path.clone();
                tokio::spawn(async move {
                    check_and_delete_file(secret_store_path + "/" + &secret_id.to_string() + ".bin")
                        .await
                });
            }
        }
    }
}
