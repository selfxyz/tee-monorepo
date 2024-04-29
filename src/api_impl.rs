use actix_web::web::{Data, Json};
use actix_web::{delete, get, post, HttpResponse, Responder};
use anyhow::Context;
use ethers::abi::{encode_packed, Token};
use ethers::prelude::*;
use ethers::utils::keccak256;
use hex::FromHex;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use log::info;
use std::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::contract_abi::{CommonChainGatewayContract, RequestChainContract};
use crate::model::{
    AppState, CommonChainClient, InjectKeyInfo, Job, RegisterEnclaveInfo, RequestChainClient, RequestChainData
};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
}

#[post("/inject-key")]
async fn inject_key(Json(key): Json<InjectKeyInfo>, app_state: Data<AppState>) -> impl Responder {
    // let mut gw_contract = app_state.gateway_contract_object.lock().unwrap();
    // let mut jobs_contract = app_state.jobs_contract_object.lock().unwrap();

    let mut wallet_gaurd = app_state.wallet.lock().unwrap();

    // if gw_contract.is_some() && jobs_contract.is_some() {
    if wallet_gaurd.is_some() {
        return HttpResponse::BadRequest().body("Secret key has already been injected");
    }

    let mut bytes32_key = [0u8; 32];
    if let Err(err) = hex::decode_to_slice(&key.operator_secret[2..], &mut bytes32_key) {
        return HttpResponse::BadRequest().body(format!(
            "Failed to hex decode the key into 32 bytes: {}",
            err
        ));
    }

    let signer_wallet = LocalWallet::from_bytes(&bytes32_key);
    let Ok(signer_wallet) = signer_wallet else {
        return HttpResponse::BadRequest().body(format!(
            "Invalid secret key provided: {}",
            signer_wallet.unwrap_err()
        ));
    };
    let signer_wallet = signer_wallet.with_chain_id(app_state.common_chain_id);
    // let signer_address = signer_wallet.address();

    // let http_rpc_client = Provider::<Http>::try_connect(&app_state.common_chain_http_url).await;
    // let Ok(http_rpc_client) = http_rpc_client else {
    //     return HttpResponse::InternalServerError().body(format!(
    //         "Failed to connect to the http rpc server {}: {}",
    //         app_state.common_chain_http_url,
    //         http_rpc_client.unwrap_err()
    //     ));
    // };
    // let http_rpc_client = Arc::new(
    //     http_rpc_client
    //         .with_signer(signer_wallet.clone())
    //         .nonce_manager(signer_address),
    // );

    // app_state.job_contract_object = Some(CommonChainJobsContractApi::new(
    //     app_state.job_contract_addr,
    //     http_rpc_client,
    // ));

    *wallet_gaurd = Some(signer_wallet);

    HttpResponse::Ok().body("Secret key injected successfully")
}

#[post("/register")]
async fn register_enclave(
    Json(enclave_info): Json<RegisterEnclaveInfo>,
    app_state: Data<AppState>,
) -> impl Responder {
    let mut is_registered = app_state.registered.lock().unwrap();
    if *is_registered {
        return HttpResponse::BadRequest().body("Enclave has already been registered.");
    }
    let Some(wallet) = app_state.wallet.lock().unwrap().clone() else {
        return HttpResponse::BadRequest().body("Operator secret key not injected yet!");
    };

    // Convert hexadecimal string into bytes
    let Ok(attestation) = hex::decode(&enclave_info.attestation[2..]) else {
        return HttpResponse::BadRequest().body("Invalid format of attestation.");
    };
    let Ok(pcr_0) = hex::decode(&enclave_info.pcr_0[2..]) else {
        return HttpResponse::BadRequest().body("Invalid format of pcr_0.");
    };
    let Ok(pcr_1) = hex::decode(&enclave_info.pcr_1[2..]) else {
        return HttpResponse::BadRequest().body("Invalid format of pcr_1.");
    };
    let Ok(pcr_2) = hex::decode(&enclave_info.pcr_2[2..]) else {
        return HttpResponse::BadRequest().body("Invalid format of pcr_2.");
    };

    let signer_wallet = wallet.clone().with_chain_id(app_state.common_chain_id);
    let signer_address = signer_wallet.address();

    let mut chain_list: Vec<RequestChainData> = vec![];
    let mut request_chain_clients: HashMap<u64, Arc<RequestChainClient>> = HashMap::new();

    let http_rpc_client = Provider::<Http>::try_connect(&app_state.common_chain_http_url).await;
    let Ok(http_rpc_client) = http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to connect to the http rpc server {}: {}",
            app_state.common_chain_http_url,
            http_rpc_client.unwrap_err()
        ));
    };
    let http_rpc_client = Arc::new(
        http_rpc_client
            .with_signer(signer_wallet.clone())
            .nonce_manager(signer_address),
    );

    let gateway_contract =
        CommonChainGatewayContract::new(app_state.gateway_contract_addr, http_rpc_client.clone());

    for chain in enclave_info.chain_list.clone() {
        let signer_wallet = wallet.clone().with_chain_id(chain);
        // get request chain rpc url
        let (contract_address, http_rpc_url, ws_rpc_url) = gateway_contract
            .request_chains(chain.into())
            .await
            .context("Failed to get request chain data")
            .unwrap();
        let http_rpc_client = Provider::<Http>::try_connect(http_rpc_url.as_str()).await;
        let Ok(http_rpc_client) = http_rpc_client else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to connect to the http rpc server {}: {}",
                http_rpc_url,
                http_rpc_client.unwrap_err()
            ));
        };

        let http_rpc_client = Arc::new(
            http_rpc_client
                .with_signer(signer_wallet)
                .nonce_manager(signer_address),
        );
        // prepare transaction
        let contract = RequestChainContract::new(contract_address, http_rpc_client.clone());
        let txn = contract.register_gateway(
            attestation.clone().into(),
            app_state.enclave_pub_key.clone().into(),
            pcr_0.clone().into(),
            pcr_1.clone().into(),
            pcr_2.clone().into(),
            enclave_info.timestamp.into(),
        );

        let pending_txn = txn.send().await;
        let Ok(pending_txn) = pending_txn else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to send transaction for registering the enclave on request chain {}: {}",
                chain,
                pending_txn.unwrap_err()
            ));
        };

        let txn_hash = pending_txn.tx_hash();
        let Ok(Some(_txn_receipt)) = pending_txn.confirmations(1).await else {
            // TODO: FIX CONFIRMATIONS REQUIRED
            return HttpResponse::InternalServerError().body(format!(
                "Failed to confirm transaction with hash {}",
                txn_hash
            ));
        };
        chain_list.push(RequestChainData {
            chain_id: chain.into(),
            contract_address,
            http_rpc_url: http_rpc_url.to_string(),
        });

        // Http RPC client for RPC
        let req_chain_client = Arc::from(RequestChainClient {
            chain_id: chain,
            contract_address: contract_address,
            contract,
            ws_rpc_url: ws_rpc_url.to_string(),
        });
        request_chain_clients.insert(chain, req_chain_client);
    }

    // let mut hasher = Keccak::v256();
    // hasher.update(b"|chain_list|");
    // encode chain list in ethabi encoder
    let token_list = Token::Array(
        enclave_info
            .chain_list
            .clone()
            .into_iter()
            .map(|x| Token::Uint(x.into()))
            .collect::<Vec<Token>>(),
    );
    let encoded_chain_ids = encode_packed(&[token_list]).unwrap();
    let hashed_chain_ids = keccak256(&encoded_chain_ids);
    // hasher.update(&encoded_chain_ids);
    // let mut hash = [0u8; 32];
    // hasher.finalize(&mut hash);

    let sig = app_state
        .enclave_signer_key
        .sign_prehash_recoverable(&hashed_chain_ids);
    let Ok((rs, v)) = sig else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the chain ID list: {}",
            sig.unwrap_err()
        ));
    };

    let Ok(signature) = Bytes::from_hex(hex::encode(rs.to_bytes().append(27 + v.to_byte()))) else {
        return HttpResponse::InternalServerError()
            .body("Failed to parse the signature into eth bytes");
    };

    let txn = gateway_contract.register_gateway(
        attestation.into(),
        app_state.enclave_pub_key.clone().into(),
        pcr_0.into(),
        pcr_1.into(),
        pcr_2.into(),
        enclave_info.timestamp.into(),
        enclave_info
            .chain_list
            .clone()
            .into_iter()
            .map(|x| U256::from(x))
            .collect(),
        signature,
        enclave_info.stake_amount.into(),
    );

    let pending_txn = txn.send().await;
    let Ok(pending_txn) = pending_txn else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to send transaction for registering the enclave on Common chain: {}",
            pending_txn.unwrap_err()
        ));
    };

    let txn_hash = pending_txn.tx_hash();
    let Ok(Some(txn_receipt)) = pending_txn.confirmations(1).await else {
        // TODO: FIX CONFIRMATIONS REQUIRED
        return HttpResponse::InternalServerError().body(format!(
            "Failed to confirm transaction with hash {}",
            txn_hash
        ));
    };

    *is_registered = true;
    app_state
        .chain_list
        .lock()
        .unwrap()
        .append(&mut chain_list.clone());

    let gateway_state_epoch_waitlist: Arc<RwLock<HashMap<u64, Vec<Job>>>> = Arc::new(RwLock::new(HashMap::new()));

    // Start contract event listner
    let contract_client = Arc::new(
        CommonChainClient::new(
            app_state.enclave_signer_key.clone(),
            app_state.enclave_pub_key.clone().into(),
            signer_wallet,
            &app_state.common_chain_ws_url,
            http_rpc_client.clone(),
            &app_state.gateway_contract_addr,
            &app_state.job_contract_addr,
            app_state.gateway_epoch_state.clone(),
            enclave_info.chain_list,
            app_state.epoch,
            app_state.time_interval,
            request_chain_clients,
            gateway_state_epoch_waitlist,
        )
        .await,
    );

    // Listen for new jobs and handles them.
    info!("Starting the contract event listener.");

    tokio::spawn(async move {
        let _ = contract_client.run(http_rpc_client).await;
    });

    HttpResponse::Ok().body(format!(
        "Enclave Node successfully registered on the common chain block {}, hash {}",
        txn_receipt.block_number.unwrap_or(0.into()),
        txn_receipt.transaction_hash
    ))
}

#[delete("/deregister")]
async fn deregister_enclave(app_state: Data<AppState>) -> impl Responder {
    let mut is_registered = app_state.registered.lock().unwrap();
    if !*is_registered {
        return HttpResponse::BadRequest().body("Enclave is not registered yet.");
    }

    let Some(signer_wallet) = app_state.wallet.lock().unwrap().clone() else {
        return HttpResponse::BadRequest().body("Operator secret key not injected yet!");
    };
    let signer_address = signer_wallet.address();

    let http_rpc_client = Provider::<Http>::try_connect(&app_state.common_chain_http_url).await;
    let Ok(http_rpc_client) = http_rpc_client else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to connect to the http rpc server {}: {}",
            app_state.common_chain_http_url,
            http_rpc_client.unwrap_err()
        ));
    };
    let http_rpc_client = Arc::new(
        http_rpc_client
            .with_signer(signer_wallet.clone())
            .nonce_manager(signer_address),
    );

    let gateway_contract =
        CommonChainGatewayContract::new(app_state.gateway_contract_addr, http_rpc_client.clone());

    let txn = gateway_contract.deregister_gateway(app_state.enclave_pub_key.clone().into());
    let pending_txn = txn.send().await;
    let Ok(pending_txn) = pending_txn else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to send transaction for deregistering the enclave node: {}",
            pending_txn.unwrap_err()
        ));
    };

    let txn_hash = pending_txn.tx_hash();
    let Ok(Some(txn_receipt)) = pending_txn.confirmations(1).await else {
        // TODO: FIX CONFIRMATIONS REQUIRED
        return HttpResponse::InternalServerError().body(format!(
            "Failed to confirm transaction with hash {}",
            txn_hash
        ));
    };

    for chain in app_state.chain_list.lock().unwrap().clone() {
        let signer_wallet = signer_wallet.clone().with_chain_id(chain.chain_id);

        let http_rpc_client = Provider::<Http>::try_connect(chain.http_rpc_url.as_str()).await;
        let Ok(http_rpc_client) = http_rpc_client else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to connect to the http rpc server {}: {}",
                chain.http_rpc_url,
                http_rpc_client.unwrap_err()
            ));
        };

        let http_rpc_client = Arc::new(
            http_rpc_client
                .with_signer(signer_wallet)
                .nonce_manager(signer_address),
        );

        let contract = RequestChainContract::new(chain.contract_address, Arc::new(http_rpc_client));

        let txn = contract.deregister_gateway(app_state.enclave_pub_key.clone().into());

        let pending_txn = txn.send().await;
        let Ok(pending_txn) = pending_txn else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to send transaction for deregistering the enclave node: {}",
                pending_txn.unwrap_err()
            ));
        };

        let txn_hash = pending_txn.tx_hash();
        let Ok(Some(_txn_receipt)) = pending_txn.confirmations(1).await else {
            // TODO: FIX CONFIRMATIONS REQUIRED
            return HttpResponse::InternalServerError().body(format!(
                "Failed to confirm transaction with hash {}",
                txn_hash
            ));
        };
    }

    *is_registered = false;
    app_state.chain_list.lock().unwrap().clear();

    HttpResponse::Ok().body(format!(
        "Enclave Node successfully deregistered from the common chain block {}, hash {}",
        txn_receipt.block_number.unwrap_or(0.into()),
        txn_receipt.transaction_hash
    ))
}
