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
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract_abi::{
    GatewayJobsContract, GatewaysContract, RelayContract, RelaySubscriptionsContract,
};
use crate::model::{
    AppState, ContractsClient, GatewayData, GatewayDetailsResponse, ImmutableConfig, MutableConfig,
    RequestChainClient, RequestChainData, SignedRegistrationBody, SignedRegistrationResponse,
};
use crate::HttpProviderType;

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
    let owner_address = H160::from_str(&immutable_config.owner_address_hex);
    let Ok(owner_address) = owner_address else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid owner address provided: {:?}",
            owner_address.unwrap_err()
        ));
    };

    let mut immutable_params_injected_guard = app_state.immutable_params_injected.lock().unwrap();
    if *immutable_params_injected_guard {
        return HttpResponse::BadRequest().body("Immutable params already configured!");
    }

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

    let mut wallet_guard = app_state.wallet.lock().unwrap();
    if *wallet_guard == Some(gas_wallet.clone()) {
        return HttpResponse::NotAcceptable().body("The same wallet address already set.");
    }

    let contracts_client_guard = app_state.contracts_client.lock().unwrap();

    if contracts_client_guard.is_some() {
        info!("Updating Contracts Client with the new wallet address");
        let gas_address = gas_wallet.address();

        // Build Common Chain http rpc client
        let common_chain_http_rpc_client =
            Provider::<Http>::try_from(&app_state.common_chain_http_url);
        let Ok(common_chain_http_rpc_client) = common_chain_http_rpc_client else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to connect to the common chain http rpc server {}: {}",
                app_state.common_chain_http_url,
                common_chain_http_rpc_client.unwrap_err()
            ));
        };
        let common_chain_http_rpc_client = Arc::new(
            common_chain_http_rpc_client
                .with_signer(gas_wallet.clone())
                .nonce_manager(gas_address),
        );

        // Build Request Chain Client's http rpc client
        let mut request_chain_contract_clients: HashMap<
            u64,
            (
                RelayContract<HttpProviderType>,
                RelaySubscriptionsContract<HttpProviderType>,
            ),
        > = HashMap::new();
        let request_chain_clients_clone: HashMap<u64, Arc<RequestChainClient>> =
            contracts_client_guard
                .as_ref()
                .unwrap()
                .request_chain_clients
                .clone();
        for (&chain_id, request_chain_client) in request_chain_clients_clone.iter() {
            let request_chain_http_rpc_client =
                Provider::<Http>::try_from(&request_chain_client.http_rpc_url);
            let Ok(request_chain_http_rpc_client) = request_chain_http_rpc_client else {
                return HttpResponse::InternalServerError().body(format!(
                    "Failed to connect to the request chain {} http rpc server {}: {}",
                    chain_id,
                    request_chain_client.http_rpc_url,
                    request_chain_http_rpc_client.unwrap_err()
                ));
            };

            let gas_wallet = gas_wallet.clone().with_chain_id(chain_id);
            let request_chain_http_rpc_client = Arc::new(
                request_chain_http_rpc_client
                    .with_signer(gas_wallet.clone())
                    .nonce_manager(gas_address),
            );

            let relay_contract = RelayContract::new(
                request_chain_client.relay_address,
                request_chain_http_rpc_client.clone(),
            );

            let relay_subs_contract = RelaySubscriptionsContract::new(
                request_chain_client.relay_subscriptions_address,
                request_chain_http_rpc_client,
            );
            request_chain_contract_clients.insert(chain_id, (relay_contract, relay_subs_contract));
        }

        // Updating Gateway Jobs Contract's http rpc client with the new wallet address
        let gateway_jobs_contract = GatewayJobsContract::new(
            app_state.gateway_jobs_contract_addr,
            common_chain_http_rpc_client,
        );

        let mut gateway_jobs_contract_write_guard = contracts_client_guard
            .as_ref()
            .unwrap()
            .gateway_jobs_contract
            .write()
            .unwrap();
        *gateway_jobs_contract_write_guard = gateway_jobs_contract;

        // Updating request chain contract's http rpc client with the new wallet address
        for request_chain_client in contracts_client_guard
            .as_ref()
            .unwrap()
            .request_chain_clients
            .values()
        {
            let (relay_contract, relay_subs_contract) = request_chain_contract_clients
                .get(&request_chain_client.chain_id)
                .unwrap()
                .clone();

            let mut relay_contract_write_guard =
                request_chain_client.relay_contract.write().unwrap();
            *relay_contract_write_guard = relay_contract;

            let mut relay_subs_contract_write_guard = request_chain_client
                .relay_subscriptions_contract
                .write()
                .unwrap();
            *relay_subs_contract_write_guard = relay_subs_contract;
        }
    }
    *wallet_guard = Some(gas_wallet.clone());

    app_state
        .mutable_params_injected
        .store(true, Ordering::SeqCst);

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
        if app_state.registered.load(Ordering::SeqCst) {
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

    {
        // verify that the app state request chain ids are same as the signed registration body chain ids
        let request_chain_ids_guard = app_state.request_chain_ids.lock().unwrap();
        if !request_chain_ids_guard.is_empty() && *request_chain_ids_guard != chain_ids {
            return HttpResponse::BadRequest().json(json!({
                    "message": "Request chain ids mismatch!",
                    "chain_ids": *request_chain_ids_guard,
            }));
        }
    }

    // if immutable or mutable params are not configured, return error
    if !*app_state.immutable_params_injected.lock().unwrap() {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!");
    }

    // if mutable params are not configured, return error
    if !app_state.mutable_params_injected.load(Ordering::SeqCst) {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!");
    }

    // if wallet is not configured, return error
    if app_state.wallet.lock().unwrap().is_none() {
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

    let chain_ids_tokens: Vec<Token> = (&chain_ids)
        .into_iter()
        .map(|&x| Token::Uint(x.into()))
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
    let common_chain_http_rpc_client = Provider::<Http>::try_from(&app_state.common_chain_http_url);
    let Ok(common_chain_http_rpc_client) = common_chain_http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to connect to the common chain http rpc server {}: {}",
            app_state.common_chain_http_url,
            common_chain_http_rpc_client.unwrap_err()
        ));
    };
    let common_chain_http_rpc_client = Arc::new(common_chain_http_rpc_client);
    let gateways_contract = GatewaysContract::new(
        app_state.gateways_contract_addr,
        common_chain_http_rpc_client.clone(),
    );

    let Ok(common_chain_block_number) = common_chain_http_rpc_client.get_block_number().await
    else {
        return HttpResponse::InternalServerError().body(
                format!("Failed to fetch the latest block number of the common chain for initiating event listening!")
            );
    };

    let mut request_chains_data: HashMap<u64, RequestChainData> = HashMap::new();

    // iterate over all chain ids and get their registration signatures
    for &chain_id in &chain_ids {
        // get request chain rpc url
        let request_chain_info = gateways_contract.request_chains(U256::from(chain_id)).await;
        if request_chain_info.is_err() {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to fetch the request chain data for chain id {}: {}",
                chain_id,
                request_chain_info.unwrap_err()
            ));
        }
        let (relay_address, relay_subscriptions_address, http_rpc_url, ws_rpc_url) =
            request_chain_info.unwrap();

        let http_rpc_client = Provider::<Http>::try_from(&http_rpc_url);
        let Ok(http_rpc_client) = http_rpc_client else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to connect to the request chain {} http rpc server {}: {}",
                chain_id,
                http_rpc_url,
                http_rpc_client.unwrap_err()
            ));
        };

        let block_number = http_rpc_client
            .get_block_number()
            .await
            .context("Failed to get the latest block number of the request chain")
            .unwrap()
            .as_u64();

        request_chains_data.insert(
            chain_id,
            RequestChainData {
                relay_address,
                relay_subscriptions_address,
                http_rpc_url: http_rpc_url.to_string(),
                ws_rpc_url: ws_rpc_url.to_string(),
                block_number,
            },
        );
    }

    let wallet_guard = app_state.wallet.lock().unwrap();

    let signer_wallet = wallet_guard
        .clone()
        .unwrap()
        .with_chain_id(app_state.common_chain_id);
    let signer_address = signer_wallet.address();

    let common_chain_http_rpc_client = Provider::<Http>::try_from(&app_state.common_chain_http_url);
    let Ok(common_chain_http_rpc_client) = common_chain_http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to connect to the common chain http rpc server {}: {}",
            app_state.common_chain_http_url,
            common_chain_http_rpc_client.unwrap_err()
        ));
    };
    let common_chain_http_rpc_client = Arc::new(
        common_chain_http_rpc_client
            .with_signer(signer_wallet.clone())
            .nonce_manager(signer_address),
    );

    let mut request_chain_clients: HashMap<u64, Arc<RequestChainClient>> = HashMap::new();

    for &chain_id in &chain_ids {
        let request_chain_data = request_chains_data.get(&chain_id).unwrap();

        let signer_wallet = wallet_guard.clone().unwrap().with_chain_id(chain_id);

        let request_chain_http_rpc_client =
            Provider::<Http>::try_from(&request_chain_data.http_rpc_url);
        let Ok(request_chain_http_rpc_client) = request_chain_http_rpc_client else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to connect to the request chain {} http rpc server {}: {}",
                chain_id,
                request_chain_data.http_rpc_url,
                request_chain_http_rpc_client.unwrap_err()
            ));
        };

        let request_chain_http_rpc_client = Arc::new(
            request_chain_http_rpc_client
                .with_signer(signer_wallet)
                .nonce_manager(signer_address),
        );
        let relay_contract = RelayContract::new(
            request_chain_data.relay_address,
            request_chain_http_rpc_client.clone(),
        );

        let relay_subs_contract = RelaySubscriptionsContract::new(
            request_chain_data.relay_subscriptions_address,
            request_chain_http_rpc_client.clone(),
        );

        let request_chain_client = Arc::from(RequestChainClient {
            chain_id,
            relay_address: request_chain_data.relay_address,
            relay_subscriptions_address: request_chain_data.relay_subscriptions_address,
            relay_contract: Arc::new(RwLock::new(relay_contract)),
            relay_subscriptions_contract: Arc::new(RwLock::new(relay_subs_contract)),
            ws_rpc_url: request_chain_data.ws_rpc_url.to_string(),
            http_rpc_url: request_chain_data.http_rpc_url.to_string(),
            request_chain_start_block_number: request_chain_data.block_number,
            confirmation_blocks: 5, // TODO: fetch from contract
            last_seen_block: Arc::new(0.into()),
        });
        request_chain_clients.insert(chain_id, request_chain_client);
    }

    let mut request_chain_ids_guard = app_state.request_chain_ids.lock().unwrap();
    if request_chain_ids_guard.is_empty() {
        *request_chain_ids_guard = chain_ids.clone();
    } else {
        if *request_chain_ids_guard != chain_ids {
            return HttpResponse::BadRequest().json(json!({
                "message": "Request chain ids mismatch!",
                "chain_ids": *request_chain_ids_guard,
            }));
        }
    }

    let mut registration_events_listener_active_guard = app_state
        .registration_events_listener_active
        .lock()
        .unwrap();

    if *registration_events_listener_active_guard == false {
        let mut contracts_client_guard = app_state.contracts_client.lock().unwrap();

        let gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let gateway_epoch_state_waitlist = Arc::new(RwLock::new(HashMap::new()));

        let gateway_jobs_contract = GatewayJobsContract::new(
            app_state.gateway_jobs_contract_addr,
            common_chain_http_rpc_client.clone(),
        );

        let subscription_job_instance_heap = Arc::new(RwLock::new(BinaryHeap::new()));
        let subscription_jobs = Arc::new(RwLock::new(HashMap::new()));

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
            offset_for_epoch: app_state.offset_for_epoch,
            gateway_epoch_state_waitlist,
            common_chain_start_block_number: Arc::new(Mutex::new(
                common_chain_block_number.as_u64(),
            )),
            subscription_job_instance_heap,
            subscription_jobs,
        });

        *contracts_client_guard = Some(Arc::clone(&contracts_client));

        let app_state_clone = app_state.clone();
        tokio::spawn(async move {
            contracts_client
                .wait_for_registration(app_state_clone)
                .await;
        });

        *registration_events_listener_active_guard = true;
    }

    let response = SignedRegistrationResponse {
        owner: enclave_owner,
        sign_timestamp: sign_timestamp.try_into().unwrap(),
        chain_ids: signed_registration_body.chain_ids,
        common_chain_signature,
        request_chain_signature,
    };

    HttpResponse::Ok().json(response)
}

// Endpoint exposed to retrieve gateway enclave details
#[get("/gateway-details")]
async fn get_gateway_details(app_state: Data<AppState>) -> impl Responder {
    if !*app_state.immutable_params_injected.lock().unwrap() {
        return HttpResponse::BadRequest().body("Immutable params not configured yet!");
    }

    if !app_state.mutable_params_injected.load(Ordering::SeqCst) {
        return HttpResponse::BadRequest().body("Mutable params not configured yet!");
    }

    let response = GatewayDetailsResponse {
        enclave_public_key: "0x".to_string()
            + &hex::encode(
                &app_state
                    .enclave_signer_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()[1..],
            ),
        enclave_address: app_state.enclave_address,
        owner_address: *app_state.enclave_owner.lock().unwrap(),
        gas_address: app_state.wallet.lock().unwrap().clone().unwrap().address(),
    };

    HttpResponse::Ok().json(response)
}

#[cfg(test)]
mod api_impl_tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::str::FromStr;

    use abi::{encode, encode_packed, Token};
    use actix_web::{body::MessageBody, http};
    use ethers::types::{Address, H160};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use serde_json::json;

    use crate::test_util::{
        generate_app_state, new_app, CHAIN_ID, GAS_WALLET_KEY, GAS_WALLET_PUBLIC_ADDRESS,
        OWNER_ADDRESS,
    };

    // Test the response for the 'index' endpoint
    #[tokio::test]
    async fn index_test() {
        let app_state = generate_app_state().await;
        let app = actix_web::test::init_service(new_app(app_state.clone())).await;

        let req = actix_web::test::TestRequest::get().uri("/").to_request();
        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    // Test the various response cases for the 'immutable-config' endpoint
    #[tokio::test]
    async fn inject_immutable_config_test() {
        let app_state = generate_app_state().await;
        let app = actix_web::test::init_service(new_app(app_state.clone())).await;

        // Inject invalid hex address string
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "0x32255"
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid owner address provided: Invalid input length".as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), H160::zero());

        // Inject invalid hex character address
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "0xzfffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid owner address provided: Invalid character 'z' at position 0".as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), H160::zero());

        // Inject a valid address
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.enclave_owner.lock().unwrap(),
            H160::from_str(OWNER_ADDRESS).unwrap()
        );

        // Inject the valid address again
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params already configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.enclave_owner.lock().unwrap(),
            H160::from_str(OWNER_ADDRESS).unwrap()
        );
    }

    fn wallet_from_hex(hex: &str) -> LocalWallet {
        let mut bytes32 = [0u8; 32];
        let _ = hex::decode_to_slice(hex, &mut bytes32);
        LocalWallet::from_bytes(&bytes32)
            .unwrap()
            .with_chain_id(CHAIN_ID)
    }

    // Test the various response cases for the 'mutable-config' endpoint
    #[tokio::test]
    async fn inject_mutable_config_test() {
        let app_state = generate_app_state().await;
        let app = actix_web::test::init_service(new_app(app_state.clone())).await;

        // Inject invalid hex private key string
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "0x32255"
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the gas private key into 32 bytes: OddLength".as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.lock().unwrap(), None);

        // Inject invalid private(signing) key
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the gas private key into 32 bytes: InvalidStringLength"
                .as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.lock().unwrap(), None);

        // Inject invalid gas private key hex string (not ecdsa valid key)
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid gas private key provided: EcdsaError(signature::Error { source: None })"
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(*app_state.wallet.lock().unwrap(), None);

        // Inject a valid private key for gas wallet
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.wallet.lock().unwrap(),
            Some(wallet_from_hex(GAS_WALLET_KEY))
        );
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(app_state.contracts_client.lock().unwrap().is_none());
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());

        // Build contracts client to verify the contracts client public address
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                    "chain_ids": [CHAIN_ID]
            }))
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .gateway_jobs_contract
                .read()
                .unwrap()
                .client()
                .inner()
                .signer()
                .address(),
            GAS_WALLET_PUBLIC_ADDRESS.parse::<Address>().unwrap()
        );

        // Inject the same valid private key for gas wallet again
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "The same wallet address already set."
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.wallet.lock().unwrap(),
            Some(wallet_from_hex(GAS_WALLET_KEY))
        );
        assert_eq!(
            app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .gateway_jobs_contract
                .read()
                .unwrap()
                .client()
                .inner()
                .signer()
                .address(),
            GAS_WALLET_PUBLIC_ADDRESS.parse::<Address>().unwrap()
        );

        const GAS_WALLET_KEY_2: &str =
            "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
        const GAS_WALLET_PUBLIC_ADDRESS_2: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

        // Inject another valid private key for gas wallet
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY_2
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert_eq!(
            *app_state.wallet.lock().unwrap(),
            Some(wallet_from_hex(GAS_WALLET_KEY_2))
        );
        assert_eq!(
            app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .gateway_jobs_contract
                .read()
                .unwrap()
                .client()
                .inner()
                .signer()
                .address(),
            GAS_WALLET_PUBLIC_ADDRESS_2.parse::<Address>().unwrap()
        );
    }

    fn recover_key(
        chain_ids: Vec<u64>,
        enclave_owner: H160,
        sign_timestamp: usize,
        common_chain_signature: String,
        request_chain_signature: String,
        verifying_key: VerifyingKey,
    ) -> bool {
        let common_chain_register_typehash =
            keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestamp)");

        let chain_ids = chain_ids.into_iter().collect::<BTreeSet<u64>>();
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

        let domain_separator = keccak256(encode(&[
            Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
            Token::FixedBytes(keccak256("marlin.oyster.Gateways").to_vec()),
            Token::FixedBytes(keccak256("1").to_vec()),
        ]));

        let digest = encode_packed(&[
            Token::String("\x19\x01".to_string()),
            Token::FixedBytes(domain_separator.to_vec()),
            Token::FixedBytes(hash_struct.to_vec()),
        ])
        .unwrap();
        let digest = keccak256(digest);

        let signature = Signature::from_slice(
            hex::decode(&common_chain_signature[0..128])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let v =
            RecoveryId::try_from((hex::decode(&common_chain_signature[128..]).unwrap()[0]) - 27)
                .unwrap();
        let common_chain_recovered_key =
            VerifyingKey::recover_from_prehash(&digest, &signature, v).unwrap();

        if common_chain_recovered_key != verifying_key {
            return false;
        }

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
        ])
        .unwrap();
        let digest = keccak256(digest);

        let signature = Signature::from_slice(
            hex::decode(&request_chain_signature[0..128])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let v =
            RecoveryId::try_from((hex::decode(&request_chain_signature[128..]).unwrap()[0]) - 27)
                .unwrap();
        let request_chain_recovered_key =
            VerifyingKey::recover_from_prehash(&digest, &signature, v).unwrap();

        if request_chain_recovered_key != verifying_key {
            return false;
        }

        true
    }

    #[tokio::test]
    async fn export_signed_registration_message_test() {
        let app_state = generate_app_state().await;
        let app = actix_web::test::init_service(new_app(app_state.clone())).await;

        // Get signature without injecting the operator's address or gas key
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params not configured yet!"
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Inject a valid address into the enclave
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature without injecting a gas key
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params not configured yet!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Inject a valid private key
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with invalid chain id
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": ["invalid u64"]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert!(resp.into_body().try_into_bytes().unwrap().starts_with(
            "Json deserialize error: invalid type: string \"invalid u64\"".as_bytes()
        ));
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with no chain_ids field in json
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({}))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert!(resp
            .into_body()
            .try_into_bytes()
            .unwrap()
            .starts_with("Json deserialize error: missing field `chain_ids`".as_bytes()));
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with valid data points
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                    "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<SignedRegistrationResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let mut chain_id_set: HashSet<u64> = HashSet::new();
        chain_id_set.insert(CHAIN_ID);

        let verifying_key = app_state.enclave_signer_key.verifying_key().to_owned();

        let response = response.unwrap();
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), chain_id_set);
        assert_eq!(response.owner, *app_state.enclave_owner.lock().unwrap());
        assert_eq!(response.common_chain_signature.len(), 130);
        assert_eq!(response.request_chain_signature.len(), 130);
        assert!(recover_key(
            vec![CHAIN_ID],
            *app_state.enclave_owner.lock().unwrap(),
            response.sign_timestamp,
            response.common_chain_signature,
            response.request_chain_signature,
            verifying_key
        ));

        // Get signature again with the same chain ids
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<SignedRegistrationResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let mut chain_id_set: HashSet<u64> = HashSet::new();
        chain_id_set.insert(CHAIN_ID);

        let verifying_key = app_state.enclave_signer_key.verifying_key().to_owned();

        let response = response.unwrap();
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(app_state.mutable_params_injected.load(Ordering::SeqCst));
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), chain_id_set);
        assert_eq!(response.owner, *app_state.enclave_owner.lock().unwrap());
        assert_eq!(response.common_chain_signature.len(), 130);
        assert_eq!(response.request_chain_signature.len(), 130);
        assert!(recover_key(
            vec![CHAIN_ID],
            *app_state.enclave_owner.lock().unwrap(),
            response.sign_timestamp,
            response.common_chain_signature,
            response.request_chain_signature,
            verifying_key
        ));

        // Get signature with a different chain id
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID + 1]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            json!({
                    "message": "Request chain ids mismatch!",
                    "chain_ids": [CHAIN_ID],
            })
            .to_string()
            .try_into_bytes()
            .unwrap()
        );

        // After on chain registration
        app_state.registered.store(true, Ordering::SeqCst);

        // Get signature after registration
        let req = actix_web::test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave has already been registered."
        );
    }

    #[tokio::test]
    async fn get_gateway_details_test() {
        let app_state = generate_app_state().await;
        let app = actix_web::test::init_service(new_app(app_state.clone())).await;

        // Get gateway details without adding wallet and gas key
        let req = actix_web::test::TestRequest::get()
            .uri("/gateway-details")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params not configured yet!"
        );

        // Inject a valid address into the enclave
        let req = actix_web::test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!"
        );

        // Get gateway details without gas key
        let req = actix_web::test::TestRequest::get()
            .uri("/gateway-details")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params not configured yet!"
        );

        // Inject a valid private gas key
        let req = actix_web::test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );

        // Get gateway details
        let req = actix_web::test::TestRequest::get()
            .uri("/gateway-details")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<GatewayDetailsResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let response = response.unwrap();
        let expected_response = GatewayDetailsResponse {
            enclave_public_key: "0x".to_string()
                + &hex::encode(
                    &app_state
                        .enclave_signer_key
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()[1..],
                ),
            enclave_address: app_state.enclave_address,
            owner_address: *app_state.enclave_owner.lock().unwrap(),
            gas_address: app_state.wallet.lock().unwrap().clone().unwrap().address(),
        };
        assert_eq!(
            response.enclave_public_key,
            expected_response.enclave_public_key
        );
        assert_eq!(response.enclave_address, expected_response.enclave_address);
        assert_eq!(response.owner_address, expected_response.owner_address);
        assert_eq!(response.gas_address, expected_response.gas_address);
    }
}
