use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use actix_web::web::Data;
use tokio::time::interval;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::utils::{generate_txn, AppState, SecretsTxnMetadata, SEND_TRANSACTION_BUFFER};

// TODO: Add support for marking secret stores dead based on absence of alive acknowledgement under a timeout
// Periodic job for sending alive acknowledgement transaction
pub async fn store_alive_monitor(app_state: Data<AppState>) {
    // Start the periodic job with interval 'MARK_ALIVE_TIMEOUT - SEND_TRANSACTION_BUFFER'
    let mut interval = interval(Duration::from_secs(
        app_state.mark_alive_timeout - SEND_TRANSACTION_BUFFER,
    ));

    loop {
        interval.tick().await; // Wait for the next tick

        // If enclave is deregistered, stop the job because acknowledgments won't be accepted then
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }

        let txn_data = generate_txn(app_state.clone(), &SecretsTxnMetadata::MarkStoreAlive);
        let Ok(txn_data) = txn_data else {
            eprintln!(
                "Failed to generate acknowledgement timeout transaction data: {:?}",
                txn_data.unwrap_err()
            );
            return;
        };

        let http_rpc_txn_manager = app_state
            .http_rpc_txn_manager
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        // Send the txn response with the mark alive counterpart
        if let Err(err) = Retry::spawn(
            ExponentialBackoff::from_millis(5).map(jitter).take(3),
            || async {
                http_rpc_txn_manager
                    .clone()
                    .call_contract_function(
                        app_state.secret_manager_contract_addr,
                        txn_data.clone(),
                        Instant::now() + Duration::from_secs(SEND_TRANSACTION_BUFFER),
                    )
                    .await
            },
        )
        .await
        {
            eprintln!("Failed to send store alive transaction: {:?}", err);
        };
    }
}
