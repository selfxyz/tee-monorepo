use abi::encode;
use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use anyhow::Context;
use ethers::abi::{encode_packed, Token};
use ethers::prelude::*;
use ethers::utils::keccak256;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use log::info;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract_abi::{GatewayJobsContract, GatewaysContract, RelayContract};
use crate::model::{
    AppState, ContractsClient, GatewayData, ImmutableConfig, MutableConfig, RequestChainClient,
    RequestChainData, SignedRegistrationBody,
};

#[get("/")]
async fn index() -> impl Responder {
    info!("Ping successful!");
    HttpResponse::Ok()
}

// Endpoint exposed to inject immutable gateway config parameters
#[post("/immutable-config")]
async fn inject_immutable_config(
    Json(immutable_config): Json<ImmutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard == true {
        return HttpResponse::BadRequest().body("Immutable params already configured!");
    }

    let owner_address = H160::from_str(&immutable_config.owner_address_hex);
    let Ok(owner_address) = owner_address else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid owner address provided: {:?}",
            owner_address.unwrap_err()
        ));
    };

    // Initialize owner address for the enclave
    *app_state.enclave_owner.lock().unwrap() = owner_address;
    *immutable_params_injected_guard = true;

    info!("Immutable params configured!");

    HttpResponse::Ok().body("Immutable params configured!")
}

// Endpoint exposed to inject mutable gateway config parameters
#[post("/mutable-config")]
async fn inject_mutable_config(
    Json(mutable_config): Json<MutableConfig>,
    app_state: Data<AppState>,
) -> impl Responder {
    let mut mutable_params_injected_guard = app_state.mutable_params_injected.lock().unwrap();

    let mut wallet_gaurd = app_state.wallet.lock().unwrap();

    let mut bytes32_gas_key = [0u8; 32];
    if let Err(err) = hex::decode_to_slice(&mutable_config.gas_key_hex, &mut bytes32_gas_key) {
        return HttpResponse::BadRequest().body(format!(
            "Failed to hex decode the gas private key into 32 bytes: {:?}",
            err
        ));
    }

    // Initialize local wallet with operator's gas key to send signed transactions to the common chain and request chains
    let gas_wallet = LocalWallet::from_bytes(&bytes32_gas_key);
    let Ok(gas_wallet) = gas_wallet else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid gas private key provided: {:?}",
            gas_wallet.unwrap_err()
        ));
    };
    let gas_wallet = gas_wallet.with_chain_id(app_state.common_chain_id);
    *wallet_gaurd = Some(gas_wallet);

    *mutable_params_injected_guard = true;

    info!("Mutable params configured!");

    HttpResponse::Ok().body("Mutable params configured!")
}

// Endpoint exposed to retrieve the metadata required to register the enclave on the common chain and request chains
#[get("/signed-registration-message")]
async fn export_signed_registration_message(
    Json(signed_registration_body): Json<SignedRegistrationBody>,
    app_state: Data<AppState>,
) -> impl Responder {
    // if gateway is already registered, return error
    {
        let is_registered = app_state.registered.lock().unwrap();
        if *is_registered {
            return HttpResponse::BadRequest().body("Enclave has already been registered.");
        }
    }

    // check if event listener is active and verify the request_chain_ids
    let chain_ids: HashSet<u64> = signed_registration_body
        .chain_ids
        .clone()
        .into_iter()
        .collect();

    // there should be atleast one request chain id
    if chain_ids.is_empty() {
        return HttpResponse::BadRequest().body("Atleast one request chain id is required!");
    }

    let mut registration_events_listener_active_guard = app_state
        .registration_events_listener_active
        .lock()
        .unwrap();
    if *registration_events_listener_active_guard == true {
        // verify that the app state request chain ids are same as the signed registration body chain ids
        let request_chain_ids_guard = app_state.request_chain_ids.lock().unwrap();
        if *request_chain_ids_guard != chain_ids {
            return HttpResponse::BadRequest().json(json!({
                    "message": "Request chain ids mismatch!",
                    "chain_ids": *request_chain_ids_guard,
            }));
        }
    }

    // if immutable or mutable params are not configured, return error
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!");
    }

    // if mutable params are not configured, return error
    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!");
    }

    // if wallet is not configured, return error
    let Some(wallet) = app_state.wallet.lock().unwrap().clone() else {
        return HttpResponse::BadRequest().body("Mutable param wallet not configured yet!");
    };

    // generate common chain signature
    let enclave_owner = app_state.enclave_owner.lock().unwrap().clone();
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let common_chain_register_typehash =
        keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestamp)");

    let chain_ids_tokens: Vec<Token> = chain_ids
        .clone()
        .into_iter()
        .map(|x| Token::Uint(x.into()))
        .collect::<Vec<Token>>();

    let chain_ids_bytes = keccak256(encode_packed(&[Token::Array(chain_ids_tokens)]).unwrap());
    let hash_struct = keccak256(encode(&[
        Token::FixedBytes(common_chain_register_typehash.to_vec()),
        Token::Address(enclave_owner),
        Token::FixedBytes(chain_ids_bytes.into()),
        Token::Uint(sign_timestamp.into()),
    ]));

    let gateways_domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.Gateways").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));

    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(gateways_domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);

    let Ok(digest) = digest else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to encode the registration message for signing: {:?}",
            digest.unwrap_err()
        ));
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = app_state
        .enclave_signer_key
        .sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the registration message using enclave key: {:?}",
            sig.unwrap_err()
        ));
    };
    let common_chain_signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    // generate request chain signatures
    let signer_wallet = wallet.clone().with_chain_id(app_state.common_chain_id);
    let signer_address = signer_wallet.address();

    // create request chain signature and add it to the request chain signatures map
    let request_chain_register_typehash =
        keccak256("Register(address owner,uint256 signTimestamp)");
    let hash_struct = keccak256(encode(&[
        Token::FixedBytes(request_chain_register_typehash.to_vec()),
        Token::Address(enclave_owner),
        Token::Uint(sign_timestamp.into()),
    ]));

    let request_chain_domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.Relay").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));

    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(request_chain_domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);

    let Ok(digest) = digest else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to encode the registration message for signing: {:?}",
            digest.unwrap_err()
        ));
    };

    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = app_state
        .enclave_signer_key
        .sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the registration message using enclave key: {:?}",
            sig.unwrap_err()
        ));
    };

    let request_chain_signature = hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec());

    // Create GatewaysContract instance
    let http_rpc_client = Provider::<Http>::try_connect(&app_state.common_chain_http_url).await;
    let Ok(http_rpc_client) = http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to connect to the common chain http rpc server {}: {}",
            app_state.common_chain_http_url,
            http_rpc_client.unwrap_err()
        ));
    };
    let http_rpc_client = Arc::new(
        http_rpc_client
            .with_signer(signer_wallet.clone())
            .nonce_manager(signer_address),
    );
    let gateways_contract =
        GatewaysContract::new(app_state.gateways_contract_addr, http_rpc_client.clone());

    let mut request_chain_data: Vec<RequestChainData> = vec![];
    let mut request_chain_clients: HashMap<u64, Arc<RequestChainClient>> = HashMap::new();

    // iterate over all request chain ids and get their registration signatures
    for &chain_id in &chain_ids {
        // create request chain client and add it to the request chain clients map
        let signer_wallet = wallet.clone().with_chain_id(chain_id);
        // get request chain rpc url
        let (contract_address, http_rpc_url, ws_rpc_url) = gateways_contract
            .request_chains(chain_id.into())
            .await
            .context("Failed to get request chain data")
            .unwrap();
        let http_rpc_url: String = http_rpc_url.to_string();
        let ws_rpc_url: String = ws_rpc_url.to_string();

        let http_rpc_client = Provider::<Http>::try_connect(&http_rpc_url).await;
        let Ok(http_rpc_client) = http_rpc_client else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to connect to the request chain {} http rpc server {}: {}",
                chain_id,
                http_rpc_url,
                http_rpc_client.unwrap_err()
            ));
        };

        let http_rpc_client = Arc::new(
            http_rpc_client
                .with_signer(signer_wallet)
                .nonce_manager(signer_address),
        );
        let contract = RelayContract::new(contract_address, http_rpc_client.clone());

        let request_chain_block_number = http_rpc_client
            .get_block_number()
            .await
            .context("Failed to get the latest block number of the request chain")
            .unwrap()
            .as_u64();

        request_chain_data.push(RequestChainData {
            chain_id: chain_id.into(),
            contract_address,
            http_rpc_url,
            ws_rpc_url: ws_rpc_url.clone(),
        });

        let request_chain_client = Arc::from(RequestChainClient {
            chain_id,
            contract_address,
            contract,
            ws_rpc_url,
            request_chain_start_block_number: request_chain_block_number,
        });
        request_chain_clients.insert(chain_id, request_chain_client);
    }

    app_state
        .request_chain_data
        .lock()
        .unwrap()
        .append(&mut request_chain_data.clone());

    if *registration_events_listener_active_guard == false {
        let Ok(common_chain_block_number) = http_rpc_client.get_block_number().await else {
            return HttpResponse::InternalServerError().body(
                format!("Failed to fetch the latest block number of the common chain for initiating event listening!")
            );
        };

        let gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let gateway_epoch_state_waitlist = Arc::new(RwLock::new(HashMap::new()));

        let gateway_jobs_contract = GatewayJobsContract::new(
            app_state.gateway_jobs_contract_addr,
            http_rpc_client.clone(),
        );

        let contracts_client = Arc::new(ContractsClient {
            enclave_owner,
            enclave_signer_key: app_state.enclave_signer_key.clone(),
            enclave_address: app_state.enclave_address,
            common_chain_ws_url: app_state.common_chain_ws_url.clone(),
            common_chain_http_url: app_state.common_chain_http_url.clone(),
            gateways_contract_address: app_state.gateways_contract_addr,
            gateway_jobs_contract: Arc::new(RwLock::new(gateway_jobs_contract)),
            request_chain_clients,
            gateway_epoch_state,
            request_chain_ids: chain_ids.clone(),
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            current_jobs: Arc::new(RwLock::new(HashMap::new())),
            epoch: app_state.epoch,
            time_interval: app_state.time_interval,
            gateway_epoch_state_waitlist,
            common_chain_start_block_number: Arc::new(Mutex::new(
                common_chain_block_number.as_u64(),
            )),
        });

        *app_state.contracts_client.lock().unwrap() = Some(Arc::clone(&contracts_client));

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            contracts_client
                .wait_for_registration(app_state_clone)
                .await;
        });

        *app_state.request_chain_ids.lock().unwrap() = chain_ids.clone();

        *registration_events_listener_active_guard = true;
        drop(registration_events_listener_active_guard);
    }

    HttpResponse::Ok().json(json!({
        "owner": enclave_owner,
        "sign_timestamp": sign_timestamp,
        "chain_ids": signed_registration_body.chain_ids,
        "common_chain_signature": common_chain_signature,
        "request_chain_signature": request_chain_signature,
    }))
}

// Endpoint exposed to retrieve gateway enclave details
#[get("/gateway-details")]
async fn get_gateway_details(app_state: Data<AppState>) -> impl Responder {
    if *app_state.immutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!");
    }

    if *app_state.mutable_params_injected.lock().unwrap() == false {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!");
    }

    HttpResponse::Ok().json(json!({
        "enclave_address": app_state.enclave_address,
        "owner_address": *app_state.enclave_owner.lock().unwrap(),
        "gas_address": app_state.wallet.lock().unwrap().clone().unwrap().address(),
    }))
}
