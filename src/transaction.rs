use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Identity, Provider, ProviderBuilder, RootProvider, WalletProvider};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::transports::http::Http;
use reqwest::{Client, Url};
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::constants::{
    GARBAGE_COLLECT_INTERVAL_SEC, GAS_INCREMENT_AMOUNT, HTTP_SLEEP_TIME,
    RESEND_GAS_PRICE_INCREMENT_PERCENT, RESEND_INTERVAL,
};
use crate::errors::TxnManagerSendError;
use crate::models::{Transaction, TxnManager, TxnStatus};
use crate::utils::{parse_send_error, verify_gas_wallet, verify_rpc_url};

type HttpProvider = FillProvider<
    JoinFill<Identity, WalletFiller<EthereumWallet>>,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

impl TxnManager {
    pub async fn new(
        rpc_url: String,
        chain_id: u64,
        gas_wallet: Arc<RwLock<String>>,
        gas_price_increment_percent: Option<u128>,
        gas_limit_increment_amount: Option<u64>,
        garbage_collect_interval_sec: Option<u64>,
    ) -> Result<Arc<Self>, TxnManagerSendError> {
        match verify_rpc_url(&rpc_url) {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        match verify_gas_wallet(&gas_wallet).await {
            Ok(_) => (),
            Err(e) => return Err(e),
        }

        let txn_manager = Arc::new(Self {
            rpc_url,
            chain_id,
            gas_wallet,
            nonce_to_send: Arc::new(RwLock::new(0)),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            gas_price_increment_percent: gas_price_increment_percent
                .unwrap_or(RESEND_GAS_PRICE_INCREMENT_PERCENT),
            gas_limit_increment_amount: gas_limit_increment_amount.unwrap_or(GAS_INCREMENT_AMOUNT),
            transactions_queue: Arc::new(RwLock::new(VecDeque::new())),
            garbage_collect_interval_sec: garbage_collect_interval_sec
                .unwrap_or(GARBAGE_COLLECT_INTERVAL_SEC),
        });

        let txn_manager_clone = txn_manager.clone();
        tokio::spawn(async move {
            let _ = txn_manager_clone.process_transaction().await;
        });

        let txn_manager_clone = txn_manager.clone();
        tokio::spawn(async move {
            txn_manager_clone.garbage_collect_transactions().await;
        });

        Ok(txn_manager)
    }

    pub async fn call_contract_function(
        self: Arc<Self>,
        contract_address: Address,
        data: Bytes,
        timeout: Instant,
    ) -> Result<String, TxnManagerSendError> {
        let mut update_nonce = false;

        let mut transaction = Transaction {
            id: uuid::Uuid::new_v4().to_string(),
            contract_address,
            data: data.clone(),
            timeout,
            gas_wallet: self.gas_wallet.read().await.clone(),
            nonce: None,
            txn_hash: None,
            status: TxnStatus::Sending,
            gas_price: 0,
            estimated_gas: 0,
            last_monitored: Instant::now(),
        };

        let mut failure_reason = String::new();

        while Instant::now() < timeout {
            let provider = match self.clone().create_provider(&transaction, false).await {
                Ok(provider) => provider,
                Err(err) => {
                    failure_reason = err.to_string();
                    continue;
                }
            };

            let res = self
                .clone()
                .manage_nonce(&provider, &mut transaction, update_nonce)
                .await;
            if res.is_err() {
                let err = res.err().unwrap();
                match err {
                    TxnManagerSendError::Timeout(err) => {
                        if !err.is_empty() {
                            failure_reason = err;
                        }
                    }
                    _ => {
                        failure_reason = err.to_string();
                    }
                }
                continue;
            }

            let transaction_request = TransactionRequest::default()
                .with_to(transaction.contract_address)
                .with_input(transaction.data.clone())
                .with_nonce(transaction.nonce.unwrap());

            if transaction.gas_price == 0 || transaction.estimated_gas == 0 {
                let res = self
                    .clone()
                    .estimate_gas_limit_and_price(
                        &provider,
                        &mut transaction,
                        transaction_request.clone(),
                    )
                    .await;
                if res.is_err() {
                    let err = res.err().unwrap();
                    match err {
                        TxnManagerSendError::Timeout(err) => {
                            if !err.is_empty() {
                                failure_reason = err;
                            }
                        }
                        _ => {
                            failure_reason = err.to_string();
                        }
                    }
                    continue;
                }
            }

            let transaction_request = transaction_request
                .with_gas_limit(transaction.estimated_gas)
                .with_gas_price(transaction.gas_price);

            let pending_txn = provider.send_transaction(transaction_request).await;
            let pending_txn = match pending_txn {
                Ok(pending_txn) => pending_txn,
                Err(err) => {
                    failure_reason = err.to_string();
                    let txn_manager_err = parse_send_error(failure_reason.clone());
                    match txn_manager_err {
                        TxnManagerSendError::NonceTooLow(_) => {
                            update_nonce = true;
                            continue;
                        }
                        TxnManagerSendError::OutOfGas(_) => {
                            update_nonce = false;
                            transaction.estimated_gas =
                                transaction.estimated_gas + self.gas_limit_increment_amount;
                            continue;
                        }
                        TxnManagerSendError::GasPriceLow(_) => {
                            update_nonce = false;
                            transaction.gas_price = transaction.gas_price
                                * (100 + self.gas_price_increment_percent)
                                / 100;
                            continue;
                        }
                        // Break in case the contract execution is failing for this txn
                        // Or the gas required is way high compared to block gas limit
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            return Err(txn_manager_err);
                        }
                        _ => {
                            update_nonce = false;
                            sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    }
                }
            };
            let txn_hash = *pending_txn.tx_hash();

            transaction.txn_hash = Some(txn_hash.to_string());
            transaction.status = TxnStatus::Pending;
            transaction.last_monitored = Instant::now();

            self.transactions
                .write()
                .await
                .insert(transaction.id.clone(), transaction.clone());

            self.transactions_queue
                .write()
                .await
                .push_back(transaction.clone());

            return Ok(transaction.id);
        }

        Err(TxnManagerSendError::Timeout(failure_reason))
    }

    async fn process_transaction(self: Arc<Self>) -> Result<(), TxnManagerSendError> {
        loop {
            let Some(mut transaction) = self.transactions_queue.write().await.pop_front() else {
                sleep(Duration::from_millis(HTTP_SLEEP_TIME)).await;
                continue;
            };
            let resend_txn_interval = RESEND_INTERVAL
                - min(
                    RESEND_INTERVAL,
                    transaction.last_monitored.elapsed().as_secs(),
                );

            sleep(Duration::from_secs(min(
                resend_txn_interval,
                transaction.timeout.elapsed().as_secs(),
            )))
            .await;

            let provider = self
                .clone()
                .create_provider(&transaction, true)
                .await
                .unwrap();

            let txn_hash = transaction.txn_hash.clone().unwrap();

            if Retry::spawn(
                ExponentialBackoff::from_millis(2)
                    .factor(100)
                    .max_delay(Duration::from_secs(2))
                    .map(jitter)
                    .take(10),
                || async {
                    self.clone()
                        .get_transaction_receipt(provider.clone(), txn_hash.clone())
                        .await
                },
            )
            .await
            .is_ok()
            {
                transaction.status = TxnStatus::Confirmed;
                transaction.last_monitored = Instant::now();

                let mut transactions_guard = self.transactions.write().await;
                transactions_guard.insert(transaction.id.clone(), transaction.clone());
                continue;
            }

            let mut send_dummy = false;

            let txn_hash = self.clone().resend_transaction(&mut transaction).await;
            match txn_hash {
                Ok(()) => (),
                Err(
                    TxnManagerSendError::NonceTooLow(_) | TxnManagerSendError::GasWalletChanged(_),
                ) => continue,
                Err(_) => {
                    send_dummy = true;
                }
            };

            if send_dummy {
                self.clone().send_dummy_transaction(&mut transaction).await;
            }
        }
    }

    pub async fn get_transaction_status(self: Arc<Self>, txn_hash: String) -> Option<TxnStatus> {
        let transactions = self.transactions.read().await.clone();
        transactions.get(&txn_hash).map(|txn| txn.status.clone())
    }

    async fn get_transaction_receipt(
        self: Arc<Self>,
        provider: HttpProvider,
        txn_hash: String,
    ) -> Result<TransactionReceipt, TxnManagerSendError> {
        let receipt = provider
            .get_transaction_receipt(txn_hash.parse().unwrap())
            .await;
        if receipt.is_err() {
            return Err(TxnManagerSendError::NetworkConnectivity(
                "Failed to get transaction receipt. Error: ".to_string()
                    + &receipt.err().unwrap().to_string(),
            ));
        }

        let receipt = receipt.unwrap();
        if receipt.is_none() {
            return Err(TxnManagerSendError::ReceiptNotFound(
                "Transaction receipt not found.".to_string(),
            ));
        }

        Ok(receipt.unwrap())
    }

    async fn resend_transaction(
        self: Arc<Self>,
        transaction: &mut Transaction,
    ) -> Result<(), TxnManagerSendError> {
        transaction.status = TxnStatus::Sending;

        transaction.estimated_gas = transaction.estimated_gas + self.gas_limit_increment_amount;
        transaction.gas_price =
            transaction.gas_price * (100 + self.gas_price_increment_percent) / 100;

        let transaction_request = TransactionRequest::default()
            .with_to(transaction.contract_address)
            .with_input(transaction.data.clone())
            .with_nonce(transaction.nonce.unwrap())
            .with_gas_limit(transaction.estimated_gas)
            .with_gas_price(transaction.gas_price);

        let mut failure_reason = String::new();

        while Instant::now() < transaction.timeout {
            let provider = self.clone().create_provider(&transaction, false).await;
            let provider = match provider {
                Ok(provider) => provider,
                Err(TxnManagerSendError::GasWalletChanged(err_msg)) => {
                    let self_clone = self.clone();
                    let transaction_clone = transaction.clone();
                    tokio::spawn(async move {
                        let _ = self_clone
                            .call_contract_function(
                                transaction_clone.contract_address,
                                transaction_clone.data,
                                transaction_clone.timeout,
                            )
                            .await;
                    });
                    failure_reason = err_msg;
                    break;
                }
                Err(err) => {
                    failure_reason = err.to_string();
                    continue;
                }
            };

            let pending_txn = provider.send_transaction(transaction_request.clone()).await;
            let pending_txn = match pending_txn {
                Ok(pending_txn) => pending_txn,
                Err(err) => {
                    failure_reason = err.to_string();
                    let err = parse_send_error(failure_reason.clone());
                    match err {
                        TxnManagerSendError::NonceTooLow(_) => {
                            break;
                        }
                        TxnManagerSendError::OutOfGas(_) => {
                            transaction.estimated_gas =
                                transaction.estimated_gas + self.gas_limit_increment_amount;
                            continue;
                        }
                        TxnManagerSendError::GasPriceLow(_) => {
                            transaction.gas_price = transaction.gas_price
                                * (100 + self.gas_price_increment_percent)
                                / 100;
                            continue;
                        }
                        // Break in case the contract execution is failing for this txn
                        // Or the gas required is way high compared to block gas limit
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            return Err(err);
                        }
                        err => {
                            failure_reason = err.to_string();
                            sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    }
                }
            };

            let txn_hash = pending_txn.tx_hash().to_string();

            transaction.status = TxnStatus::Pending;
            transaction.last_monitored = Instant::now();

            let mut transactions_guard = self.transactions.write().await;

            transactions_guard.remove(&transaction.id.clone());
            transaction.txn_hash = Some(txn_hash.clone());

            transactions_guard.insert(transaction.id.clone(), transaction.clone());

            return Ok(());
        }

        return Err(TxnManagerSendError::Timeout(failure_reason));
    }

    async fn send_dummy_transaction(self: Arc<Self>, transaction: &mut Transaction) {
        loop {
            let dummy_txn = TransactionRequest::default()
                .with_to(self.gas_wallet.read().await.parse().unwrap())
                .with_value(U256::ZERO)
                .with_nonce(transaction.nonce.unwrap())
                .with_gas_limit(transaction.estimated_gas)
                .with_gas_price(transaction.gas_price);

            let provider = self
                .clone()
                .create_provider(&transaction, true)
                .await
                .unwrap();

            let pending_txn = provider.send_transaction(dummy_txn).await;
            let Ok(pending_txn) = pending_txn else {
                let err = parse_send_error(pending_txn.err().unwrap().to_string());
                match err {
                    TxnManagerSendError::NonceTooLow(_) => {
                        break;
                    }
                    TxnManagerSendError::OutOfGas(_) => {
                        transaction.estimated_gas =
                            transaction.estimated_gas + self.gas_limit_increment_amount;
                        continue;
                    }
                    TxnManagerSendError::GasPriceLow(_) => {
                        transaction.gas_price =
                            transaction.gas_price * (100 + self.gas_price_increment_percent) / 100;
                        continue;
                    }
                    _ => {
                        sleep(Duration::from_millis(HTTP_SLEEP_TIME)).await;
                        continue;
                    }
                }
            };

            let tx_hash = pending_txn.watch().await.unwrap();
            transaction.txn_hash = Some(tx_hash.to_string());
            transaction.status = TxnStatus::Failed;
            transaction.last_monitored = Instant::now();

            let mut transactions_guard = self.transactions.write().await;
            transactions_guard.insert(transaction.id.clone(), transaction.clone());

            break;
        }
    }

    async fn create_provider(
        self: Arc<Self>,
        transaction: &Transaction,
        ignore_gas_wallet_check: bool,
    ) -> Result<HttpProvider, TxnManagerSendError> {
        if !ignore_gas_wallet_check
            && transaction.gas_wallet != self.gas_wallet.read().await.clone()
        {
            return Err(TxnManagerSendError::GasWalletChanged(
                "Gas wallet changed".to_string(),
            ));
        }
        let signer: PrivateKeySigner = transaction.gas_wallet.parse().unwrap();
        let signer = signer.with_chain_id(Some(self.chain_id));
        let signer_wallet = EthereumWallet::from(signer);

        Ok(ProviderBuilder::new()
            .wallet(signer_wallet)
            .on_http(Url::parse(&self.rpc_url).unwrap()))
    }

    async fn manage_nonce(
        self: Arc<Self>,
        provider: &HttpProvider,
        transaction: &mut Transaction,
        update_nonce: bool,
    ) -> Result<(), TxnManagerSendError> {
        let mut failure_reason = String::new();

        while Instant::now() < transaction.timeout {
            let mut current_nonce: u64 = 0;
            if update_nonce {
                let gas_wallet = provider.wallet().default_signer().address();
                let current_nonce_res = provider.get_transaction_count(gas_wallet).await;
                current_nonce = match current_nonce_res {
                    Ok(current_nonce) => current_nonce,
                    Err(err) => {
                        failure_reason = err.to_string();
                        sleep(Duration::from_millis(HTTP_SLEEP_TIME)).await;
                        continue;
                    }
                };
            } else {
                if transaction.nonce.is_some() {
                    return Ok(());
                }
            }

            let mut nonce_to_send_guard = self.nonce_to_send.write().await;
            if current_nonce > *nonce_to_send_guard {
                *nonce_to_send_guard = current_nonce;
            }
            transaction.nonce = Some(*nonce_to_send_guard);
            *nonce_to_send_guard += 1;

            return Ok(());
        }

        return Err(TxnManagerSendError::Timeout(failure_reason));
    }

    async fn estimate_gas_limit_and_price(
        self: Arc<Self>,
        provider: &HttpProvider,
        transaction: &mut Transaction,
        transaction_request: TransactionRequest,
    ) -> Result<(), TxnManagerSendError> {
        let mut gas_price: u128 = 0;
        let mut failure_reason = String::new();
        while Instant::now() < transaction.timeout {
            let gas_price_res = provider.get_gas_price().await;
            gas_price = match gas_price_res {
                Ok(gas_price) => gas_price,
                Err(err) => {
                    failure_reason = err.to_string();
                    sleep(Duration::from_millis(HTTP_SLEEP_TIME)).await;
                    continue;
                }
            };

            break;
        }

        let mut estimated_gas: u64 = 0;
        while Instant::now() < transaction.timeout {
            let estimated_gas_res = provider.estimate_gas(&transaction_request).await;
            estimated_gas = match estimated_gas_res {
                Ok(estimated_gas) => estimated_gas,
                Err(err) => {
                    let err = parse_send_error(err.to_string());
                    match err {
                        TxnManagerSendError::GasTooHigh(_)
                        | TxnManagerSendError::ContractExecution(_) => {
                            return Err(err);
                        }
                        err => {
                            failure_reason = err.to_string();
                            sleep(Duration::from_millis(HTTP_SLEEP_TIME)).await;
                            continue;
                        }
                    }
                }
            };

            break;
        }

        if gas_price == 0 || estimated_gas == 0 {
            return Err(TxnManagerSendError::Timeout(failure_reason));
        }

        transaction.gas_price = gas_price;
        transaction.estimated_gas = estimated_gas;

        Ok(())
    }

    async fn garbage_collect_transactions(self: Arc<Self>) {
        loop {
            sleep(Duration::from_secs(self.garbage_collect_interval_sec)).await;

            let mut transactions_guard = self.transactions.write().await;
            let now = Instant::now();

            transactions_guard.retain(|_, transaction| {
                match transaction.status {
                    TxnStatus::Confirmed | TxnStatus::Failed => {
                        // Keep transaction if less than 10 minutes old
                        now.duration_since(transaction.last_monitored) < Duration::from_secs(600)
                    }
                    // Keep all pending and sending transactions
                    TxnStatus::Pending | TxnStatus::Sending => true,
                }
            });
        }
    }
}
