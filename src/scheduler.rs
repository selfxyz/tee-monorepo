use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use actix_web::web::Data;
use ethers::types::U256;
use tokio::sync::mpsc::Sender;
use tokio::time::interval;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::utils::{
    check_and_delete_file, open_and_read_file, AppState, SecretStoredMetadata, SecretsTxnMetadata,
    SecretsTxnType,
};

// TODO: Add support for marking secret stores dead based on absence of alive acknowledgement under a timeout
// Periodic job for monitoring stored secrets, sending alive acknowledgement for them and deleting those past their end timestamp
pub async fn secrets_monitor_and_garbage_cleaner(
    app_state: Data<AppState>,
    tx: Sender<SecretsTxnMetadata>,
) {
    // Start the periodic job with interval 'MARK_ALIVE_TIMEOUT/2'
    let mut interval = interval(Duration::from_secs(app_state.mark_alive_timeout / 2));

    loop {
        interval.tick().await; // Wait for the next tick

        // If enclave is deregistered, stop the job because acknowledgments won't be accepted then
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }

        // Clone and get the data of secrets stored inside the enclave at the moment
        let secrets_stored: Vec<(U256, SecretStoredMetadata)> = app_state
            .secrets_stored
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, secret)| (id, secret.clone()))
            .collect();

        for (secret_id, secret_stored_metadata) in secrets_stored {
            // If less than 'MARK_ALIVE_TIMEOUT/2' time has passed since the last alive timestamp of secret ID,
            // then skip its alive check in this cycle to avoid overloading
            if secret_stored_metadata
                .last_alive_time
                .elapsed()
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                < (app_state.mark_alive_timeout / 2)
            {
                continue;
            }

            // Retrieve the secret from the file it is supposed to be stored in
            let Ok(secret_data) = Retry::spawn(
                ExponentialBackoff::from_millis(5).map(jitter).take(3),
                || async {
                    open_and_read_file(
                        app_state.secret_store_path.to_owned()
                            + "/"
                            + &secret_id.to_string()
                            + ".bin",
                    )
                    .await
                },
            )
            .await
            else {
                eprintln!("Failed to read the secret id {} file location\n", secret_id);
                continue;
            };

            // If secret data stored isn't the same size as the size limit of the secret ID, don't mark it as alive
            if secret_stored_metadata.secret_metadata.size_limit != secret_data.len().into() {
                continue;
            }

            // Send txn response with the mark alive counterpart
            let _ = Retry::spawn(
                ExponentialBackoff::from_millis(5).map(jitter).take(3),
                || async {
                    tx.send(SecretsTxnMetadata {
                        txn_type: SecretsTxnType::MarkStoreAlive,
                        secret_id: secret_id,
                        retry_deadline: secret_stored_metadata.last_alive_time
                            + Duration::from_secs(app_state.mark_alive_timeout + 1),
                    })
                    .await
                },
            )
            .await;

            // If the secret ID has passed its end timestamp, remove it from the storage
            if SystemTime::now()
                > SystemTime::UNIX_EPOCH
                    + Duration::from_secs(
                        secret_stored_metadata
                            .secret_metadata
                            .end_timestamp
                            .as_u64(),
                    )
            {
                let _ = app_state.secrets_stored.lock().unwrap().remove(&secret_id);

                let _ = Retry::spawn(
                    ExponentialBackoff::from_millis(5).map(jitter).take(3),
                    || async {
                        check_and_delete_file(
                            app_state.secret_store_path.to_owned()
                                + "/"
                                + &secret_id.to_string()
                                + ".bin",
                        )
                        .await
                    },
                )
                .await;
            }
        }
    }
}
