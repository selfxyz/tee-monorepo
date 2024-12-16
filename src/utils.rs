use alloy::signers::local::PrivateKeySigner;
use reqwest::Url;

use crate::errors::TxnManagerSendError;

pub(crate) fn parse_send_error(error: String) -> TxnManagerSendError {
    let error_lowercase = error.to_lowercase();
    if error_lowercase.contains("nonce too low") {
        return TxnManagerSendError::NonceTooLow(error);
    }

    if error_lowercase.contains("nonce too high")
        || error_lowercase.contains("too many pending transactions")
    {
        return TxnManagerSendError::NonceTooHigh(error);
    }

    if error_lowercase.contains("out of gas")
        || (error_lowercase.contains("transaction requires at least")
            && error_lowercase.contains("gas but got"))
    {
        return TxnManagerSendError::OutOfGas(error);
    }

    if error_lowercase.contains("gas limit too high")
        || error_lowercase.contains("transaction exceeds block gas limit")
    {
        return TxnManagerSendError::GasTooHigh(error);
    }

    if error_lowercase.contains("gas price too low")
        || error_lowercase.contains("transaction underpriced")
    {
        return TxnManagerSendError::GasPriceLow(error);
    }

    if error_lowercase.contains("connection") || error_lowercase.contains("network") {
        return TxnManagerSendError::NetworkConnectivity(error);
    }

    if error_lowercase.contains("reverted") || error_lowercase.contains("failed") {
        return TxnManagerSendError::ContractExecution(error);
    }

    TxnManagerSendError::OtherRetryable(error)
}

pub(crate) fn verify_rpc_url(rpc_url: &str) -> Result<(), TxnManagerSendError> {
    let url = Url::parse(rpc_url);
    if url.is_err() {
        return Err(TxnManagerSendError::InvalidRpcUrl(
            url.err().unwrap().to_string(),
        ));
    }
    let url = url.unwrap();
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(TxnManagerSendError::InvalidRpcUrl(format!(
            "Invalid RPC URL: {:?}. URL must start with http or https",
            rpc_url
        )));
    }
    Ok(())
}

pub(crate) fn verify_private_signer(
    private_signer: String,
) -> Result<PrivateKeySigner, TxnManagerSendError> {
    let private_signer = private_signer.parse::<PrivateKeySigner>();
    if private_signer.is_err() {
        return Err(TxnManagerSendError::InvalidPrivateSigner(
            private_signer.err().unwrap().to_string(),
        ));
    }
    Ok(private_signer.unwrap())
}
