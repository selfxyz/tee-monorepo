use alloy::signers::local::PrivateKeySigner;
use std::sync::Arc;
use tokio::sync::RwLock;

use reqwest::Url;

use crate::errors::TxnManagerSendError;

pub(crate) fn parse_send_error(error: String) -> TxnManagerSendError {
    let error = error.to_lowercase();
    if error.contains("nonce too low") {
        return TxnManagerSendError::NonceTooLow(error);
    }

    if error.contains("nonce too high") || error.contains("too many pending transactions") {
        return TxnManagerSendError::NonceTooHigh(error);
    }

    if error.contains("out of gas")
        || (error.contains("transaction requires at least") && error.contains("gas but got"))
    {
        return TxnManagerSendError::OutOfGas(error);
    }

    if error.contains("gas limit too high") || error.contains("transaction exceeds block gas limit")
    {
        return TxnManagerSendError::GasTooHigh(error);
    }

    if error.contains("gas price too low") || error.contains("transaction underpriced") {
        return TxnManagerSendError::GasPriceLow(error);
    }

    if error.contains("connection") || error.contains("network") {
        return TxnManagerSendError::NetworkConnectivity(error);
    }

    if error.contains("reverted") || error.contains("failed") {
        return TxnManagerSendError::ContractExecution(error);
    }

    return TxnManagerSendError::OtherRetryable(error);
}

pub(crate) fn verify_rpc_url(rpc_url: &str) -> Result<(), TxnManagerSendError> {
    let url =
        Url::parse(rpc_url).map_err(|err| TxnManagerSendError::InvalidRpcUrl(err.to_string()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(TxnManagerSendError::InvalidRpcUrl(format!(
            "Invalid RPC URL: {:?}. URL must start with http or https",
            rpc_url
        )));
    }
    Ok(())
}

pub(crate) async fn verify_gas_wallet(
    gas_wallet: &Arc<RwLock<String>>,
) -> Result<(), TxnManagerSendError> {
    let gas_wallet_str = gas_wallet.read().await;
    if gas_wallet_str.is_empty() {
        return Err(TxnManagerSendError::InvalidGasWallet(
            "Empty Gas Wallet Provided".to_string(),
        ));
    }
    match gas_wallet_str.parse::<PrivateKeySigner>() {
        Ok(_) => Ok(()),
        Err(_) => Err(TxnManagerSendError::InvalidGasWallet(format!(
            "Failed to parse gas wallet. Invalid Gas Wallet Provided: {:?}",
            gas_wallet_str
        ))),
    }
}
