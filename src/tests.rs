#[cfg(test)]
mod serverless_executor_test {
    use std::collections::{BTreeMap, BTreeSet};
    use std::str::FromStr;
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use actix_web::body::MessageBody;
    use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
    use actix_web::web::Data;
    use actix_web::{http, test, App, Error};
    use ethers::abi::{encode, Token};
    use ethers::prelude::*;
    use ethers::types::{Address, Bytes as EthBytes};
    use ethers::utils::keccak256;
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use tokio::sync::mpsc::channel;
    use tokio::task;
    use tokio::time::{sleep, Duration};

    use crate::api_impl::{deregister_enclave, index, inject_key, register_enclave};
    use crate::chain_util::get_key_for_job_id;
    use crate::constant::OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE;
    use crate::model::{AppState, ComChainJobType, CommonChainClient, GatewayData, Job};

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arbitrum-sepolia.infura.io/ws/v3/cd72f20b9fd544f8a5b8da706441e01c";
    const GATEWAY_CONTRACT_ADDR: &str = "0x819d9b4087D88359B6d7fFcd16F17A13Ca79fd0E";
    const JOB_CONTRACT_ADDR: &str = "0xAc6Ae536203a3ec290ED4aA1d3137e6459f4A963";
    const REQ_CHAIN_CONTRACT_ADDR: &str = "0xaF7E4CB6B3729C65c4a9a63d89Ae04e97C9093C4";
    const WALLET_PRIVATE_KEY: &str =
        "0x083f09e4d950da6eee7eac93ba7fa046d12eb3c8ca4e4ba92487ae3526e87bda";
    const REGISTER_ATTESTATION: &str = "0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462cfa7554f87ba13620037695d62a381a2d8";
    const REGISTER_PCR_0: &str = "0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462";
    const REGISTER_PCR_1: &str = "0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";
    const REGISTER_PCR_2: &str = "0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3";
    const REGISTER_TIMESTAMP: usize = 1722134849000;
    const REGISTER_STAKE_AMOUNT: usize = 100;
    const EPOCH: u64 = 1713433800;
    const TIME_INTERVAL: u64 = 300;

    // Generate test app state
    async fn generate_app_state() -> Data<AppState> {
        // Initialize random 'secp256k1' signing key for the enclave
        let signer = SigningKey::random(&mut OsRng);
        let signer_verifier_key: [u8; 64] =
            signer.verifying_key().to_encoded_point(false).to_bytes()[1..]
                .try_into()
                .unwrap();

        Data::new(AppState {
            enclave_signer_key: signer,
            wallet: None.into(),
            common_chain_id: CHAIN_ID,
            common_chain_http_url: HTTP_RPC_URL.to_owned(),
            common_chain_ws_url: WS_URL.to_owned(),
            gateway_contract_addr: GATEWAY_CONTRACT_ADDR.parse::<Address>().unwrap(),
            job_contract_addr: JOB_CONTRACT_ADDR.parse::<Address>().unwrap(),
            chain_list: vec![].into(),
            registered: false.into(),
            enclave_pub_key: EthBytes::from(&signer_verifier_key),
            gateway_epoch_state: Arc::new(RwLock::new(BTreeMap::new())),
            epoch: EPOCH,
            time_interval: TIME_INTERVAL,
            common_chain_client: None.into(),
        })
    }

    // Return the actix server with the provided app state
    fn new_app(
        app_state: Data<AppState>,
    ) -> App<
        impl ServiceFactory<
            ServiceRequest,
            Response = ServiceResponse<impl MessageBody + std::fmt::Debug>,
            Config = (),
            InitError = (),
            Error = Error,
        >,
    > {
        App::new()
            .app_data(app_state)
            .service(index)
            .service(inject_key)
            .service(register_enclave)
            .service(deregister_enclave)
    }

    #[actix_web::test]
    // Test the various response cases for the 'inject_key' endpoint
    async fn inject_key_test() {
        let app = test::init_service(new_app(generate_app_state().await)).await;

        // Inject invalid hex private key string
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": "0x32255"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the key into 32 bytes: Odd number of digits".as_bytes()
        );

        // Inject invalid length private key
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": "0x322c322c322c332c352c35"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the key into 32 bytes: Invalid string length"
        );

        // Inject invalid private(signing) key
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid secret key provided: signature error"
        );

        // Inject a valid private key
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret key injected successfully"
        );

        // Inject the valid private key again
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret key has already been injected"
        );
    }

    #[actix_web::test]
    // Test the various response cases for the 'register_enclave' & 'deregister_enclave' endpoint
    async fn register_deregister_enclave_test() {
        let app = test::init_service(new_app(generate_app_state().await)).await;

        // Register the executor without injecting the operator's private key
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Operator secret key not injected yet!"
        );

        // Deregister the enclave without even injecting the private key
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave is not registered yet."
        );

        // Inject a valid private key into the enclave
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret key injected successfully"
        );

        // Deregister the enclave before even registering it
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave is not registered yet."
        );

        // Register the enclave with an invalid attestation hex string
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": "0x32255",
                "pcr_0": "0x",
                "pcr_1": "0x",
                "pcr_2": "0x",
                "timestamp": 2160,
                "stake_amount": 100,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid format of attestation."
        );

        // Register the enclave with valid data points
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(resp
            .into_body()
            .try_into_bytes()
            .unwrap()
            .starts_with("Enclave Node successfully registered on the common chain".as_bytes()));

        // Register the enclave again before deregistering
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave has already been registered."
        );

        sleep(Duration::from_secs(2)).await;
        // Deregister the enclave
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(resp.into_body().try_into_bytes().unwrap().starts_with(
            "Enclave Node successfully deregistered from the common chain".as_bytes()
        ));

        // Deregister the enclave again before registering it
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave is not registered yet."
        );
    }

    async fn generate_common_chain_client() -> CommonChainClient {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        test::call_service(&app, req).await;

        // Register the enclave again before deregistering
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        test::call_service(&app, req).await;

        let common_chain_client = app_state
            .common_chain_client
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        common_chain_client
    }

    async fn add_gateway_epoch_state(
        common_chain_client: Arc<CommonChainClient>,
        num: Option<u64>,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_cycle = (ts - common_chain_client.epoch - OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE)
            / common_chain_client.time_interval;

        let mut gateway_epoch_state_guard =
            common_chain_client.gateway_epoch_state.write().unwrap();
        gateway_epoch_state_guard
            .entry(current_cycle)
            .or_insert(BTreeMap::new())
            .insert(
                common_chain_client.address,
                GatewayData {
                    last_block_number: 5600 as u64,
                    address: common_chain_client.address,
                    stake_amount: U256::from(100),
                    status: true,
                    req_chain_ids: BTreeSet::from([CHAIN_ID]),
                },
            );

        let num = num.unwrap_or(1);

        for _ in 1..num {
            gateway_epoch_state_guard
                .entry(current_cycle)
                .or_insert(BTreeMap::new())
                .insert(
                    Address::random(),
                    GatewayData {
                        last_block_number: 5600 as u64,
                        address: Address::random(),
                        stake_amount: U256::from(100),
                        status: true,
                        req_chain_ids: BTreeSet::from([CHAIN_ID]),
                    },
                );
        }
    }

    async fn generate_job_relayed_log(job_id: Option<U256>, job_starttime: u64) -> Log {
        let job_id = job_id.unwrap_or(U256::from(1));

        Log {
            address: H160::from_str(REQ_CHAIN_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                )
                .into(),
                H256::from_uint(&job_id),
            ],
            data: encode(&[
                Token::FixedBytes(
                    hex::decode(
                        "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e"
                            .to_owned(),
                    )
                    .unwrap(),
                ),
                Token::Bytes(
                    serde_json::to_vec(&json!({
                        "num": 10
                    }))
                    .unwrap(),
                ),
                Token::Uint(2000.into()),
                Token::Uint(20.into()),
                Token::Uint(100.into()),
                Token::Uint(100.into()),
                Token::Uint(U256::from(job_starttime)),
            ])
            .into(),
            ..Default::default()
        }
    }

    async fn generate_generic_job(job_id: Option<U256>, job_starttime: Option<u64>) -> Job {
        let job_id = job_id.unwrap_or(U256::from(1));

        Job {
            job_id,
            req_chain_id: CHAIN_ID,
            job_key: get_key_for_job_id(job_id, CHAIN_ID).await,
            tx_hash: hex::decode(
                "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e".to_owned(),
            )
            .unwrap(),
            code_input: serde_json::to_vec(&json!({
                "num": 10
            }))
            .unwrap()
            .into(),
            user_timeout: U256::from(2000),
            starttime: U256::from(
                job_starttime.unwrap_or(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
            ),
            job_owner: H160::from_str(REQ_CHAIN_CONTRACT_ADDR).unwrap(),
            job_type: ComChainJobType::JobRelay,
            sequence_number: 1 as u8,
            gateway_address: None,
        }
    }

    #[actix_web::test]
    async fn test_get_job_from_job_relay_event() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job_starttime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log = generate_job_relayed_log(None, job_starttime).await;

        let expected_job = generate_generic_job(None, Some(job_starttime)).await;

        let job = common_chain_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await
            .unwrap();

        assert_eq!(job, expected_job);
    }

    #[actix_web::test]
    async fn test_get_job_from_job_relay_event_invalid_log() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let log = Log {
            address: H160::from_str(REQ_CHAIN_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                )
                .into(),
                H256::from_uint(&U256::from(1)),
            ],
            data: EthBytes::from(vec![0x00]),
            ..Default::default()
        };

        let job = common_chain_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await;

        // expect an error
        assert_eq!(job.err().unwrap().to_string(), "Error while decoding event");
    }

    #[actix_web::test]
    async fn test_select_gateway_for_job_id() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(common_chain_client.clone(), None).await;

        let req_chain_client = common_chain_client.req_chain_clients[&job.req_chain_id].clone();
        let gateway_address = common_chain_client
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .unwrap();

        assert_eq!(gateway_address, common_chain_client.address);
    }

    #[actix_web::test]
    async fn test_select_gateway_for_job_id_no_gateway() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job = generate_generic_job(None, None).await;

        let req_chain_client = common_chain_client.req_chain_clients[&job.req_chain_id].clone();
        let gateway_address = common_chain_client
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .unwrap();

        assert_eq!(gateway_address, Address::zero());

        let waitlisted_jobs_hashmap = common_chain_client
            .gateway_epoch_state_waitlist
            .read()
            .unwrap()
            .clone();

        let waitlisted_jobs: Vec<Vec<Job>> = waitlisted_jobs_hashmap.values().cloned().collect();

        assert_eq!(waitlisted_jobs.len(), 1);
        assert_eq!(waitlisted_jobs[0].len(), 1);
        assert_eq!(waitlisted_jobs[0][0], job);
    }

    #[actix_web::test]
    async fn test_job_placed_handler() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);
        let job_starttime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log = generate_job_relayed_log(None, job_starttime).await;

        let mut job = common_chain_client
            .clone()
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await
            .unwrap();

        add_gateway_epoch_state(common_chain_client.clone(), None).await;

        let (req_chain_tx, mut com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);

        let job_clone = job.clone();
        let common_chain_client_clone = common_chain_client.clone();
        task::spawn(async move {
            common_chain_client_clone
                .job_placed_handler(job_clone, req_chain_tx.clone())
                .await;
        });

        let mut expected_job = generate_generic_job(None, Some(job_starttime)).await;

        while let Some((rx_job, rx_com_chain_client)) = com_chain_rx.recv().await {
            job.gateway_address = Some(common_chain_client.address);
            assert_eq!(rx_job, job);

            expected_job.gateway_address = Some(common_chain_client.address);
            assert_eq!(rx_job, expected_job);

            assert_eq!(rx_com_chain_client.active_jobs.read().unwrap().len(), 1);
            assert_eq!(
                rx_com_chain_client
                    .active_jobs
                    .read()
                    .unwrap()
                    .get(&job.job_key),
                Some(&rx_job)
            );
            break;
        }
    }

    #[actix_web::test]
    async fn test_job_placed_handler_no_gateway() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job_starttime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log = generate_job_relayed_log(None, job_starttime).await;

        let job = common_chain_client
            .clone()
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await
            .unwrap();

        let expected_job = generate_generic_job(None, Some(job_starttime)).await;

        let (req_chain_tx, _) = channel::<(Job, Arc<CommonChainClient>)>(100);

        common_chain_client
            .clone()
            .job_placed_handler(job.clone(), req_chain_tx.clone())
            .await;

        let waitlisted_jobs_hashmap = common_chain_client
            .gateway_epoch_state_waitlist
            .read()
            .unwrap()
            .clone();

        let waitlisted_jobs: Vec<Vec<Job>> = waitlisted_jobs_hashmap.values().cloned().collect();

        assert_eq!(waitlisted_jobs.len(), 1);
        assert_eq!(waitlisted_jobs[0].len(), 1);
        assert_eq!(waitlisted_jobs[0][0], job);
        assert_eq!(waitlisted_jobs[0][0], expected_job);
    }

    // TODO: tests for gateway_epoch_state_service
    // TODO: tests for job_relayed_slash_timer
}
