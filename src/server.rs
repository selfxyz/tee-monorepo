use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use ecies::decrypt;
use ethers::abi::{encode, encode_packed, Token};
use ethers::prelude::*;
use ethers::utils::keccak256;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde_json::json;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::events::events_listener;
use crate::utils::{
    create_and_populate_file, AppState, CreateSecret, ImmutableConfig, MutableConfig,
    SecretsTxnMetadata, SecretsTxnType, SECRET_STORAGE_CAPACITY,
};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
}

#[post("/immutable-config")]
// Endpoint exposed to inject immutable secret store config parameters
async fn inject_immutable_config(
    Json(immutable_config): Json<ImmutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard == true {
        return HttpResponse::BadRequest().body("Immutable params already configured!\n");
    }

    let owner_address = hex::decode(
        &immutable_config
            .owner_address_hex
            .strip_prefix("0x")
            .unwrap_or(&immutable_config.owner_address_hex),
    );
    let Ok(owner_address) = owner_address else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid owner address hex string: {:?}\n",
            owner_address.unwrap_err()
        ));
    };

    if owner_address.len() != 20 {
        return HttpResponse::BadRequest().body("Owner address must be 20 bytes long!\n");
    }

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = H160::from_slice(&owner_address);
    *immutable_params_injected_guard = true;

    HttpResponse::Ok().body("Immutable params configured!\n")
}

#[post("/mutable-config")]
// Endpoint exposed to inject mutable secret store config parameters
async fn inject_mutable_config(
    Json(mutable_config): Json<MutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    let bytes32_gas_key = hex::decode(
        &mutable_config
            .gas_key_hex
            .strip_prefix("0x")
            .unwrap_or(&mutable_config.gas_key_hex),
    );
    let Ok(bytes32_gas_key) = bytes32_gas_key else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid gas private key hex string: {:?}\n",
            bytes32_gas_key.unwrap_err()
        ));
    };

    if bytes32_gas_key.len() != 32 {
        return HttpResponse::BadRequest().body("Gas private key must be 32 bytes long!\n");
    }

    // Initialize local wallet with operator's gas key to send signed transactions to the common chain
    let gas_wallet = LocalWallet::from_bytes(&bytes32_gas_key);
    let Ok(gas_wallet) = gas_wallet else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid gas private key provided: {:?}\n",
            gas_wallet.unwrap_err()
        ));
    };
    let gas_wallet = gas_wallet.with_chain_id(app_state.common_chain_id);

    // Connect the rpc http provider with the operator's gas wallet
    let http_rpc_client = Provider::<Http>::try_from(&app_state.http_rpc_url);
    let Ok(http_rpc_client) = http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to initialize the http rpc server {}: {:?}\n",
            app_state.http_rpc_url,
            http_rpc_client.unwrap_err()
        ));
    };
    let http_rpc_client = http_rpc_client.with_signer(gas_wallet);

    // Fetch current nonce for the injected gas address from the rpc
    let nonce_to_send = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            http_rpc_client
                .get_transaction_count(http_rpc_client.address(), None)
                .await
        },
    )
    .await;
    let Ok(nonce_to_send) = nonce_to_send else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to fetch current nonce for the gas address: {:?}\n",
            nonce_to_send.unwrap_err()
        ));
    };

    // Initialize HTTP RPC client and nonce for sending the signed transactions
    let mut mutable_params_injected_guard = app_state.mutable_params_injected.lock().unwrap();
    *app_state.nonce_to_send.lock().unwrap() = nonce_to_send;
    *app_state.http_rpc_client.lock().unwrap() = Some(http_rpc_client);
    *mutable_params_injected_guard = true;

    HttpResponse::Ok().body("Mutable params configured!\n")
}

#[get("/signed-registration-message")]
// Endpoint exposed to retrieve the metadata required to register the secret store on the common chain
async fn export_signed_registration_message(app_state: Data<AppState>) -> impl Responder {
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!\n");
    }

    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!\n");
    }

    let storage_capacity = SECRET_STORAGE_CAPACITY;
    let owner = app_state.enclave_owner.lock().unwrap().clone();
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Encode and hash the secret storage capacity of enclave following EIP712 format
    let domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.SecretStore").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));
    let register_typehash =
        keccak256("Register(address owner,uint256 storageCapacity,uint256 signTimestamp)");

    let hash_struct = keccak256(encode(&[
        Token::FixedBytes(register_typehash.to_vec()),
        Token::Address(owner),
        Token::Uint(storage_capacity.into()),
        Token::Uint(sign_timestamp.into()),
    ]));

    // Create the digest
    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);
    let Ok(digest) = digest else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to encode the registration message for signing: {:?}\n",
            digest.unwrap_err()
        ));
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = app_state.enclave_signer.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the registration message using enclave key: {:?}\n",
            sig.unwrap_err()
        ));
    };
    let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    let http_rpc_client = app_state.http_rpc_client.lock().unwrap().clone().unwrap();
    let current_block_number = http_rpc_client.get_block_number().await;

    let mut events_listener_active_guard = app_state.events_listener_active.lock().unwrap();
    if *events_listener_active_guard == false {
        let Ok(current_block_number) = current_block_number else {
            return HttpResponse::InternalServerError().body(format!("Failed to fetch the latest block number of the common chain for initiating event listening: {:?}\n", current_block_number.unwrap_err()));
        };

        *events_listener_active_guard = true;
        drop(events_listener_active_guard);

        tokio::spawn(async move {
            events_listener(app_state, current_block_number).await;
        });
    }

    HttpResponse::Ok().json(json!({
        "storage_capacity": storage_capacity,
        "sign_timestamp": sign_timestamp,
        "owner": owner,
        "signature": format!("0x{}", signature),
    }))
}

#[post("/inject-secret")]
async fn inject_and_store_secret(
    Json(create_secret): Json<CreateSecret>,
    app_state: Data<AppState>,
) -> impl Responder {
    if !app_state.enclave_registered.load(Ordering::SeqCst) {
        return HttpResponse::BadRequest().body("Secret store enclave not registered yet!\n");
    }

    let encrypted_secret_bytes = hex::decode(
        &create_secret
            .encrypted_secret_hex
            .strip_prefix("0x")
            .unwrap_or(&create_secret.encrypted_secret_hex),
    );
    let Ok(encrypted_secret_bytes) = encrypted_secret_bytes else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid encrypted secret hex string: {:?}\n",
            encrypted_secret_bytes.unwrap_err()
        ));
    };

    let signature_bytes = hex::decode(
        &create_secret
            .signature_hex
            .strip_prefix("0x")
            .unwrap_or(&create_secret.signature_hex),
    );
    let Ok(signature_bytes) = signature_bytes else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid signature hex string: {:?}\n",
            signature_bytes.unwrap_err()
        ));
    };

    // Reconstruct the signature
    let signature = Signature::try_from(signature_bytes.as_slice());
    let Ok(signature) = signature else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid signature : {:?}\n",
            signature.unwrap_err()
        ));
    };

    let data_hash = keccak256(encode(&[
        Token::Uint(create_secret.secret_id),
        Token::Bytes(encrypted_secret_bytes.clone()),
    ]));

    // Recover the signer address from the signature
    let recovered_address = signature.recover(data_hash);
    let Ok(recovered_address) = recovered_address else {
        return HttpResponse::BadRequest().body(format!(
            "Failed to recover the signer from the signature: {:?}\n",
            recovered_address.unwrap_err()
        ));
    };

    let decrypted_secret = decrypt(
        &app_state.enclave_signer.to_bytes(),
        &encrypted_secret_bytes,
    );
    let Ok(decrypted_secret) = decrypted_secret else {
        return HttpResponse::BadRequest().body(format!(
            "Failed to decrypt the encrypted secret using enclave private key: {:?}\n",
            decrypted_secret.unwrap_err()
        ));
    };

    let Some(secret_created) = app_state
        .secrets_created
        .lock()
        .unwrap()
        .remove(&create_secret.secret_id)
    else {
        return HttpResponse::BadRequest()
            .body("Secret ID not created yet or undergoing injection!\n");
    };

    if recovered_address != secret_created.secret_metadata.owner {
        app_state
            .secrets_created
            .lock()
            .unwrap()
            .insert(create_secret.secret_id, secret_created);
        return HttpResponse::BadRequest()
            .body("Signer address not the same as secret owner address!\n");
    }

    let secret_stored = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            create_and_populate_file(
                app_state.secret_store_path.to_owned()
                    + "/"
                    + &create_secret.secret_id.to_string()
                    + ".bin",
                &decrypted_secret,
            )
            .await
        },
    )
    .await;
    if secret_stored.is_err() {
        app_state
            .secrets_created
            .lock()
            .unwrap()
            .insert(create_secret.secret_id, secret_created);
        return HttpResponse::InternalServerError().body(format!(
            "Failed to store the secret inside the enclave: {:?}",
            secret_stored.unwrap_err()
        ));
    }

    app_state
        .secrets_stored
        .lock()
        .unwrap()
        .insert(create_secret.secret_id, secret_created.secret_metadata);

    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Encode and hash the acknowledgement of storing the secret following EIP712 format
    let domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.SecretStore").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));
    let acknowledge_typehash = keccak256("Acknowledge(uint256 secretId,uint256 signTimestamp)");

    let hash_struct = keccak256(encode(&[
        Token::FixedBytes(acknowledge_typehash.to_vec()),
        Token::Uint(create_secret.secret_id),
        Token::Uint(sign_timestamp.into()),
    ]));

    // Create the digest
    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);
    let Ok(digest) = digest else {
        return HttpResponse::InternalServerError().body(format!(
            "Secret Stored! \nFailed to encode the acknowledgement message for signing: {:?}\n",
            digest.unwrap_err()
        ));
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = app_state.enclave_signer.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Secret Stored! \nFailed to sign the acknowledgement message using enclave key: {:?}\n",
            sig.unwrap_err()
        ));
    };
    let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

    let _ = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            app_state
                .secrets_txn_sender_channel
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .send(SecretsTxnMetadata {
                    txn_type: SecretsTxnType::ACKNOWLEDGEMENT,
                    secret_id: create_secret.secret_id,
                    sign_timestamp: Some(sign_timestamp.into()),
                    signature: Some(signature.clone().into()),
                    retry_deadline: secret_created.acknowledgement_deadline,
                })
                .await
        },
    )
    .await;

    HttpResponse::Ok().json(json!({
        "secret_id": create_secret.secret_id,
        "sign_timestamp": sign_timestamp,
        "signature": format!("0x{}", hex::encode(signature)),
    }))
}

// #[post("/get-proof")]
// async fn get_proof_of_storage(
//     Json(storage_proof): Json<StorageProof>,
//     app_state: Data<AppState>,
// ) -> impl Responder {
//     let secret_data = app_state
//         .secrets_stored
//         .lock()
//         .unwrap()
//         .get(&storage_proof.secret_id)
//         .cloned();
//     let Some(secret_data) = secret_data else {
//         return HttpResponse::BadRequest().body("Secret not found!\n");
//     };

//     let secret_stored = Retry::spawn(
//         ExponentialBackoff::from_millis(5).map(jitter).take(3),
//         || async {
//             open_and_read_file(
//                 app_state.secret_store_path.to_owned()
//                     + "/"
//                     + &storage_proof.secret_id.to_string()
//                     + ".bin",
//             )
//             .await
//         },
//     )
//     .await;
//     let Ok(secret) = secret_stored else {
//         return HttpResponse::InternalServerError().body(format!(
//             "Failed to retrieve the secret stored inside the enclave: {:?}",
//             secret_stored.unwrap_err()
//         ));
//     };

//     if secret_data.size_limit != secret.len().into() {
//         return HttpResponse::InternalServerError()
//             .body("Secret stored has size below the limit!\n");
//     }

//     let sign_timestamp = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap()
//         .as_secs();

//     // Encode and hash the acknowledgement of storing the secret following EIP712 format
//     let domain_separator = keccak256(encode(&[
//         Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
//         Token::FixedBytes(keccak256("marlin.oyster.SecretStore").to_vec()),
//         Token::FixedBytes(keccak256("1").to_vec()),
//     ]));
//     let alive_typehash = keccak256("Alive(uint256 secretId,address owner,uint256 signTimestamp)");

//     let hash_struct = keccak256(encode(&[
//         Token::FixedBytes(alive_typehash.to_vec()),
//         Token::Uint(storage_proof.secret_id),
//         Token::Address(secret_data.owner),
//         Token::Uint(sign_timestamp.into()),
//     ]));

//     // Create the digest
//     let digest = encode_packed(&[
//         Token::String("\x19\x01".to_string()),
//         Token::FixedBytes(domain_separator.to_vec()),
//         Token::FixedBytes(hash_struct.to_vec()),
//     ]);
//     let Ok(digest) = digest else {
//         return HttpResponse::InternalServerError().body(format!(
//             "Secret Stored! \nFailed to encode the alive message for signing: {:?}\n",
//             digest.unwrap_err()
//         ));
//     };
//     let digest = keccak256(digest);

//     // Sign the digest using enclave key
//     let sig = app_state.enclave_signer.sign_prehash_recoverable(&digest);
//     let Ok((rs, v)) = sig else {
//         return HttpResponse::InternalServerError().body(format!(
//             "Secret Stored! \nFailed to sign the alive message using enclave key: {:?}\n",
//             sig.unwrap_err()
//         ));
//     };
//     let signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

//     HttpResponse::Ok().json(json!({
//         "secret_id": storage_proof.secret_id,
//         "sign_timestamp": sign_timestamp,
//         "signature": format!("0x{}", signature),
//     }))
// }
