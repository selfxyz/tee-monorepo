use std::cmp::min;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::web::Data;
use ethers::providers::Middleware;
use ethers::types::{TransactionRequest, U256};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::utils::*;

// Send 'SecretStore' transactions to the common chain
pub async fn send_transactions(app_state: Data<AppState>, mut rx: Receiver<SecretsTxnMetadata>) {
    let pending_txns_queue: Arc<Mutex<VecDeque<PendingTxnData>>> = Arc::new(VecDeque::new().into());

    // Spawn task for monitoring pending transactions for block confirmation and retrying when necessary
    let app_state_clone = app_state.clone();
    let pending_txns_queue_clone = pending_txns_queue.clone();
    let tx = app_state
        .secrets_txn_sender_channel
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    tokio::spawn(async move {
        resend_pending_transaction(app_state_clone, pending_txns_queue_clone, tx).await;
    });

    while let Some(secrets_txn_metadata) = rx.recv().await {
        // Initialize the txn object to send based on the txn type
        let secrets_txn = generate_txn(
            &app_state.secret_storage_contract_abi,
            app_state.secret_store_contract_addr,
            &secrets_txn_metadata,
        )
        .unwrap();

        // Initialize retry metadata like gas price, gas limit and the need to update the nonce from the rpc
        let mut update_nonce = false;
        let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
        let Some((mut gas_limit, mut gas_price)) = estimate_gas_and_price(
            http_rpc_client,
            &secrets_txn,
            secrets_txn_metadata.retry_deadline,
        )
        .await
        else {
            // If failed to retrieve gas limit and price for the txn under the deadline, then skip this txn
            continue;
        };

        // Retry loop for sending the transaction to the common chain 'SecretStore' contract
        while Instant::now() < secrets_txn_metadata.retry_deadline {
            // Initialize the signer rpc client being used for sending the transaction in this retry loop
            let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
            let mut txn = secrets_txn.clone();

            // If required retrieve the current nonce from the network and retry otherwise
            if update_nonce == true {
                let new_nonce_to_send = http_rpc_client
                    .get_transaction_count(http_rpc_client.address(), None)
                    .await;
                let Ok(new_nonce_to_send) = new_nonce_to_send else {
                    eprintln!(
                        "Failed to fetch current nonce for the gas address ({:?}): {:?}",
                        http_rpc_client.address(),
                        new_nonce_to_send.unwrap_err()
                    );

                    sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
                    continue;
                };

                // Update the nonce in the app_state
                *app_state.nonce_to_send.lock().unwrap() = new_nonce_to_send;
                update_nonce = false;
            }

            // Current nonce to use for sending the transaction in this retry loop
            let current_nonce = *app_state.nonce_to_send.lock().unwrap();

            // Update metadata to be used for sending the transaction and send it to the common chain
            let txn = txn
                .set_from(http_rpc_client.address())
                .set_nonce(current_nonce)
                .set_gas(gas_limit)
                .set_gas_price(gas_price)
                .to_owned();
            let pending_txn = http_rpc_client.send_transaction(txn, None).await;
            let Ok(pending_txn) = pending_txn else {
                let error_string = format!("{:?}", pending_txn.unwrap_err());
                eprintln!(
                    "Failed to send the secret {} transaction for secret id {}: {}",
                    secrets_txn_metadata.txn_type.as_str(),
                    secrets_txn_metadata.secret_id,
                    error_string
                );

                // Handle retry conditions based on the rpc error enum value
                match parse_send_error(error_string.to_lowercase()) {
                    RpcTxnSendError::NonceTooLow => {
                        update_nonce = true;
                        continue;
                    }
                    RpcTxnSendError::OutOfGas => {
                        gas_limit = gas_limit + GAS_LIMIT_BUFFER;
                        continue;
                    }
                    RpcTxnSendError::GasPriceLow => {
                        gas_price =
                            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT) * gas_price / 100;
                        continue;
                    }
                    // Break in case the contract execution is failing for this txn or the gas required is way high compared to block gas limit
                    RpcTxnSendError::GasTooHigh | RpcTxnSendError::ContractExecution => break,
                    _ => {
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            };

            let pending_tx_hash = pending_txn.tx_hash();
            println!(
                "Secret {} transaction successfully sent for id {} with nonce {} and hash {:?}",
                secrets_txn_metadata.txn_type.as_str(),
                secrets_txn_metadata.secret_id,
                current_nonce,
                pending_tx_hash
            );

            // Add the current sent txn to the pending txns list with the signer client included (nonce is corresponding to the current signer)
            pending_txns_queue
                .lock()
                .unwrap()
                .push_back(PendingTxnData {
                    txn_hash: pending_tx_hash,
                    txn_data: secrets_txn_metadata,
                    http_rpc_client: http_rpc_client.clone(),
                    nonce: current_nonce,
                    gas_limit: gas_limit,
                    gas_price: gas_price,
                    last_monitor_instant: Instant::now(),
                });

            // Increment nonce for the next transaction to send
            *app_state.nonce_to_send.lock().unwrap() += U256::one();
            break;
        }
    }

    println!("Transaction sender channel stopped!");
    return;
}

// Function to regularly check the pending transactions for block confirmation and resend them if not included within an interval
async fn resend_pending_transaction(
    app_state: Data<AppState>,
    pending_txns_queue: Arc<Mutex<VecDeque<PendingTxnData>>>,
    tx_sender: Sender<SecretsTxnMetadata>,
) {
    loop {
        let Some(mut pending_txn_data) = pending_txns_queue.lock().unwrap().pop_front() else {
            if !app_state.enclave_registered.load(Ordering::SeqCst) {
                // Exit if the executor has been deregistered
                return;
            }

            // Continue if the pending txns deque is empty
            sleep(Duration::from_millis(200)).await;
            continue;
        };

        // Calculate the interval to wait before checking for block confirmation of the pending txn and resending accordingly
        let resend_interval = RESEND_TXN_INTERVAL
            - min(
                RESEND_TXN_INTERVAL,
                pending_txn_data.last_monitor_instant.elapsed().as_secs(),
            );

        // Wait for the interval estimated, keeping track of the txn retry deadline as well
        sleep(Duration::from_secs(min(
            resend_interval,
            pending_txn_data
                .txn_data
                .retry_deadline
                .duration_since(Instant::now())
                .as_secs(),
        )))
        .await;

        // Get the transaction receipt for the pending transaction to check if it's still pending or had been dropped
        if Retry::spawn(
            ExponentialBackoff::from_millis(5).map(jitter).take(3),
            || async {
                pending_txn_data
                    .http_rpc_client
                    .get_transaction_receipt(pending_txn_data.txn_hash)
                    .await
            },
        )
        .await
        .is_ok_and(|receipt| receipt.is_some())
        {
            // Continue the outer loop if the txn has been mined and confirmed
            continue;
        }

        // Current pending txn needs to be resent now since it still can't be confirmed and the further txns are blocked

        // Flag to keep track of whether there is a need to send dummy txn or not
        let mut send_dummy = true;
        // Increment the gas limit and price for the replacement txn to be accepted
        pending_txn_data.gas_limit = pending_txn_data.gas_limit + GAS_LIMIT_BUFFER;
        pending_txn_data.gas_price =
            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT) * pending_txn_data.gas_price / 100;

        while Instant::now() < pending_txn_data.txn_data.retry_deadline {
            // Initialize the pending transaction data and update its metadata accordingly
            let mut replacement_txn = generate_txn(
                &app_state.secret_storage_contract_abi,
                app_state.secret_store_contract_addr,
                &pending_txn_data.txn_data,
            )
            .unwrap();

            // Check if the gas account has been updated and therefore send the replacement transaction to the main sender
            let current_gas_address = app_state
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address();
            if current_gas_address != pending_txn_data.http_rpc_client.address() {
                send_dummy = false;
                let Ok(_) = tx_sender.send(pending_txn_data.txn_data.clone()).await else {
                    continue;
                };
                break;
            }

            let replacement_txn = replacement_txn
                .set_from(pending_txn_data.http_rpc_client.address())
                .set_nonce(pending_txn_data.nonce)
                .set_gas(pending_txn_data.gas_limit)
                .set_gas_price(pending_txn_data.gas_price)
                .to_owned();

            // Send the replacement transaction for the current nonce
            let pending_txn = pending_txn_data
                .http_rpc_client
                .send_transaction(replacement_txn, None)
                .await;
            let Ok(pending_txn) = pending_txn else {
                let error_string = format!("{:?}", pending_txn.unwrap_err());

                // Handle retry logic based on the error enum value
                match parse_send_error(error_string.to_lowercase()) {
                    RpcTxnSendError::NonceTooLow => {
                        // Current nonce is already mined and need not be resent now
                        send_dummy = false;
                        break;
                    }
                    RpcTxnSendError::OutOfGas => {
                        pending_txn_data.gas_limit = pending_txn_data.gas_limit + GAS_LIMIT_BUFFER;
                        continue;
                    }
                    RpcTxnSendError::GasPriceLow => {
                        pending_txn_data.gas_price =
                            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT)
                                * pending_txn_data.gas_price
                                / 100;
                        continue;
                    }
                    // Just to be on the safer side, though very less likely to occur because the same txn has been sent successfully once
                    RpcTxnSendError::GasTooHigh | RpcTxnSendError::ContractExecution => break,
                    _ => {
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            };

            // Monitor the newly sent pending txn
            pending_txn_data.txn_hash = pending_txn.tx_hash();
            pending_txn_data.last_monitor_instant = Instant::now();
            pending_txns_queue
                .lock()
                .unwrap()
                .push_front(pending_txn_data.clone());

            send_dummy = false;
            break;
        }

        // Continue in case the replacement txn was sent successfully or the original pending txn was mined
        if send_dummy == false {
            continue;
        }

        eprintln!("Failed to resolve a pending txn with hash: {:?}, 
            sending 0 ETH to self (dummy txn) from the gas account for unblocking the current nonce {}", 
            pending_txn_data.txn_hash, pending_txn_data.nonce);

        // If the current nonce has still not been resolved for the 'SecretStore' txn within the deadline then send a dummy txn to unblock it
        loop {
            // Check if the gas account has been updated and therefore no need to unblock the current nonce for the old gas address
            let current_gas_address = app_state
                .http_rpc_client
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .address();
            if current_gas_address != pending_txn_data.http_rpc_client.address() {
                break;
            }

            // Send 0 ETH to self as a dummy replacement txn for the current nonce
            let dummy_replacement_txn =
                TransactionRequest::pay(pending_txn_data.http_rpc_client.address(), 0u64)
                    .nonce(pending_txn_data.nonce)
                    .gas(pending_txn_data.gas_limit)
                    .gas_price(pending_txn_data.gas_price);

            let pending_txn = pending_txn_data
                .http_rpc_client
                .send_transaction(dummy_replacement_txn, None)
                .await;
            let Ok(pending_txn) = pending_txn else {
                let error_string = format!("{:?}", pending_txn.unwrap_err());
                eprintln!(
                    "Failed to send the dummy replacement txn for the nonce {}: {}",
                    pending_txn_data.nonce, error_string
                );

                // Handle retry logic for the dummy txn
                match parse_send_error(error_string.to_lowercase()) {
                    RpcTxnSendError::NonceTooLow => {
                        // Txn mined for the current nonce and hence no need to retry
                        break;
                    }
                    RpcTxnSendError::OutOfGas => {
                        pending_txn_data.gas_limit = pending_txn_data.gas_limit + GAS_LIMIT_BUFFER;
                        continue;
                    }
                    RpcTxnSendError::GasPriceLow => {
                        pending_txn_data.gas_price =
                            U256::from(100 + RESEND_GAS_PRICE_INCREMENT_PERCENT)
                                * pending_txn_data.gas_price
                                / 100;
                        continue;
                    }
                    _ => {
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                }
            };

            // Wait for confirmation of the sent txn
            let Ok(Some(_)) = pending_txn
                .confirmations(1)
                .interval(Duration::from_secs(1))
                .await
            else {
                // Retry if the txn is not confirmed
                continue;
            };

            // Break if the txn is successfully confirmed
            break;
        }
    }
}
