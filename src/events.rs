use std::pin::pin;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use actix_web::web::Data;
use ethers::abi::{decode, ParamType};
use ethers::prelude::*;
use ethers::utils::keccak256;
use scopeguard::defer;
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::sleep;
use tokio_stream::Stream;

use crate::transactions::send_transactions;
use crate::utils::{
    h256_to_address, AppState, SecretCreatedMetadata, SecretMetadata, SecretsTxnMetadata,
    SecretsTxnType, ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE,
};

// Start listening to events emitted by the 'SecretStore' contract if enclave is registered else listen for Store registered event first
pub async fn events_listener(app_state: Data<AppState>, starting_block: U64) {
    defer! {
        *app_state.events_listener_active.lock().unwrap() = false;
    }
    loop {
        // web socket connection
        let web_socket_client =
            match Provider::<Ws>::connect_with_reconnects(&app_state.web_socket_url, 0).await {
                Ok(client) => client,
                Err(err) => {
                    eprintln!(
                        "Failed to connect to the common chain websocket provider: {:?}",
                        err
                    );
                    continue;
                }
            };

        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            // Create filter to listen to the 'EnclaveStoreRegistered' event emitted by the EnclaveStore contract
            let register_store_filter = Filter::new()
                .address(app_state.enclave_store_contract_addr)
                .topic0(H256::from(keccak256(
                    "EnclaveStoreRegistered(address,address,uint256)",
                )))
                .topic1(H256::from(app_state.enclave_address))
                .topic2(H256::from(*app_state.enclave_owner.lock().unwrap()))
                .from_block(starting_block);

            // Subscribe to the store registered filter through the rpc web socket client
            let mut register_stream = match web_socket_client
                .subscribe_logs(&register_store_filter)
                .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!(
                        "Failed to subscribe to EnclaveStore ({:?}) contract 'EnclaveStoreRegistered' event logs: {:?}",
                        app_state.enclave_store_contract_addr,
                        err,
                    );
                    continue;
                }
            };

            while let Some(event) = register_stream.next().await {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                app_state.enclave_registered.store(true, Ordering::SeqCst);
                app_state.last_block_seen.store(
                    event.block_number.unwrap_or(starting_block).as_u64(),
                    Ordering::SeqCst,
                );
                break;
            }

            if !app_state.enclave_registered.load(Ordering::SeqCst) {
                continue;
            }
        }

        println!("Enclave registered successfully on the common chain!");
        // Create filter to listen to 'SecretStoreCreated' and 'EnclaveAcknowledgedStore' events emitted by the SecretStore contract
        let secrets_filter = Filter::new()
            .address(app_state.secret_store_contract_addr)
            .topic0(vec![
                keccak256("SecretStoreCreated(uint256,address,uint256,uint256,uint256,address[])"),
                keccak256("EnclaveAcknowledgedStore(uint256,address)"),
            ])
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the filter through the rpc web socket client
        let secrets_stream = match web_socket_client.subscribe_logs(&secrets_filter).await {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to SecretStore ({:?}) contract 'SecretStoreCreated' & 'EnclaveAcknowledgedStore' event logs: {:?}",
                    app_state.secret_store_contract_addr, err,
                );
                continue;
            }
        };
        let secrets_stream = pin!(secrets_stream);

        // Create filter to listen to 'EnclaveStoreDeregistered' event emitted by the EnclaveStore contract
        let store_deregistered_filter = Filter::new()
            .address(app_state.enclave_store_contract_addr)
            .topic0(H256::from(keccak256("EnclaveStoreDeregistered(address)")))
            .topic1(H256::from(app_state.enclave_address))
            .from_block(app_state.last_block_seen.load(Ordering::SeqCst));
        // Subscribe to the deregistered filter through the rpc web socket client
        let store_deregistered_stream = match web_socket_client
            .subscribe_logs(&store_deregistered_filter)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!(
                    "Failed to subscribe to EnclaveStore ({:?}) contract 'EnclaveStoreDeregistered' event logs: {:?}",
                    app_state.enclave_store_contract_addr,
                    err
                );
                continue;
            }
        };
        let store_deregistered_stream = pin!(store_deregistered_stream);

        // Create tokio mpsc channel to send transactions to the common chain 'SecretStore' contract coordinated
        let (tx, rx) = channel::<SecretsTxnMetadata>(100);
        *app_state.secrets_txn_sender_channel.lock().unwrap() = Some(tx.clone());

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            send_transactions(app_state_clone, rx).await;
        });

        handle_event_logs(
            secrets_stream,
            store_deregistered_stream,
            app_state.clone(),
            tx,
        )
        .await;
        if !app_state.enclave_registered.load(Ordering::SeqCst) {
            return;
        }
    }
}

// Listen to the "EnclaveStore" & "SecretStore" contract event logs and process them accordingly
async fn handle_event_logs(
    mut secrets_stream: impl Stream<Item = Log> + Unpin,
    mut store_deregistered_stream: impl Stream<Item = Log> + Unpin,
    app_state: Data<AppState>,
    tx: Sender<SecretsTxnMetadata>,
) {
    println!("Started listening to 'SecretStore' events!");

    loop {
        select! {
            Some(event) = store_deregistered_stream.next() => {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                // Capture the Enclave deregistered event emitted by the 'EnclaveStore' contract
                println!("Enclave deregistered from the common chain!");
                app_state.enclave_registered.store(false, Ordering::SeqCst);
                *app_state.secrets_txn_sender_channel.lock().unwrap() = None;

                println!("Stopped listening to secret store events!");
                return;
            }
            Some(event) = secrets_stream.next() => {
                if event.removed.unwrap_or(true) {
                    continue;
                }

                let Some(current_block) = event.block_number else {
                    continue;
                };

                if current_block.as_u64() < app_state.last_block_seen.load(Ordering::SeqCst) {
                    continue;
                }
                app_state.last_block_seen.store(current_block.as_u64(), Ordering::SeqCst);

                // Capture the Secret created event emitted by the 'SecretStore' contract
                if event.topics[0]
                    == keccak256("SecretStoreCreated(uint256,address,uint256,uint256,uint256,address[])")
                    .into()
                {
                    // Extract the 'indexed' parameters of the event
                    let secret_id = event.topics[1].into_uint();
                    let secret_owner = h256_to_address(event.topics[2]);

                    // Decode the event parameters using the ABI information
                    let event_tokens = decode(
                        &vec![
                            ParamType::Uint(256),
                            ParamType::Uint(256),
                            ParamType::Uint(256),
                            ParamType::Array(Box::new(ParamType::Address)),
                        ],
                        &event.data.to_vec(),
                    );
                    let Ok(event_tokens) = event_tokens else {
                        eprintln!(
                            "Failed to decode 'SecretStoreCreated' event data for secret id {}: {:?}",
                            secret_id,
                            event_tokens.unwrap_err()
                        );
                        continue;
                    };

                    let Some(size_limit) = event_tokens[0].clone().into_uint() else {
                        eprintln!(
                            "Failed to decode sizeLimit token from the 'SecretStoreCreated' event data for secret id {}: {:?}",
                            secret_id,
                            event_tokens[0]
                        );
                        continue;
                    };
                    let Some(end_timestamp) = event_tokens[1].clone().into_uint() else {
                        eprintln!(
                            "Failed to decode endTimestamp token from the 'SecretStoreCreated' event data for secret id {}: {:?}",
                            secret_id,
                            event_tokens[1]
                        );
                        continue;
                    };
                    let Some(selected_nodes) = event_tokens[3].clone().into_array() else {
                        eprintln!(
                            "Failed to decode selectedEnclaves token from the 'SecretStoreCreated' event data for secret id {}: {:?}",
                            secret_id,
                            event_tokens[3]
                        );
                        continue;
                    };

                    // Mark the current secret as waiting for acknowledgements
                    app_state
                        .secrets_awaiting_acknowledgement
                        .lock()
                        .unwrap()
                        .insert(secret_id, 0);

                    let app_state_clone = app_state.clone();
                    let tx_clone = tx.clone();
                    tokio::spawn(async move {
                        handle_acknowledgement_timeout(secret_id, app_state_clone, tx_clone).await;
                    });

                    // Check if the enclave has been selected for storing the secret
                    let is_node_selected = selected_nodes
                        .into_iter()
                        .map(|token| token.into_address())
                        .filter(|addr| addr.is_some())
                        .any(|addr| addr.unwrap() == app_state.enclave_address);

                    if is_node_selected {
                        app_state.secrets_created.lock().unwrap().insert(secret_id, SecretCreatedMetadata {
                            secret_metadata: SecretMetadata {
                                owner: secret_owner,
                                size_limit: size_limit,
                                end_timestamp_millis: end_timestamp,
                            },
                            acknowledgement_deadline: Instant::now() + Duration::from_secs(app_state.acknowledgement_timeout.as_u64()),
                        });
                    }
                }
                // Capture the EnclaveAcknowledgedStore event emitted by the SecretStore contract
                else if event.topics[0]
                    == keccak256("EnclaveAcknowledgedStore(uint256,address)").into()
                {
                    let secret_id = event.topics[1].into_uint();
                    let Some(secret_ack_count) = app_state.secrets_awaiting_acknowledgement.lock().unwrap().get(&secret_id).cloned() else {
                        continue;
                    };

                    if secret_ack_count+1 == app_state.num_selected_stores {
                        // Mark the secret as acknowledged
                        app_state
                            .secrets_awaiting_acknowledgement
                            .lock()
                            .unwrap()
                            .remove(&secret_id);
                    }else {
                        app_state.secrets_awaiting_acknowledgement.lock().unwrap().insert(secret_id, secret_ack_count+1);
                    }
                }
            }
            else => break,
        }
    }

    println!("Both the 'SecretStore' and 'EnclaveStore' subscription streams have ended!");
}

// Start task to handle the acknowledgement timeout for a secret created
async fn handle_acknowledgement_timeout(
    secret_id: U256,
    app_state: Data<AppState>,
    tx: Sender<SecretsTxnMetadata>,
) {
    sleep(Duration::from_secs(
        app_state.acknowledgement_timeout.as_u64() + 1,
    ))
    .await;

    // If the secret created has been acknowledged then don't send anything
    if !app_state
        .secrets_awaiting_acknowledgement
        .lock()
        .unwrap()
        .contains_key(&secret_id)
    {
        return;
    }

    // Send txn response with acknowledgement timeout counterpart
    if let Err(err) = tx
        .send(SecretsTxnMetadata {
            txn_type: SecretsTxnType::AcknowledgementTimeout,
            secret_id: secret_id,
            sign_timestamp: None,
            signature: None,
            retry_deadline: Instant::now()
                + Duration::from_secs(ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE),
        })
        .await
    {
        eprintln!(
            "Failed to send acknowledgement timeout response to receiver channel: {:?}",
            err
        );
    }

    // Mark the secret created as deleted from enclave side
    app_state
        .secrets_awaiting_acknowledgement
        .lock()
        .unwrap()
        .remove(&secret_id);
}
