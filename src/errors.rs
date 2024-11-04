use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxnManagerSendError {
    #[error("Invalid gas wallet")]
    InvalidGasWallet,
    #[error("Invalid RPC URL")]
    InvalidRpcUrl,
    #[error("Nonce too low")]
    NonceTooLow,
    #[error("Nonce too high")]
    NonceTooHigh,
    #[error("Out of gas")]
    OutOfGas,
    #[error("Gas too high")]
    GasTooHigh,
    #[error("Gas price low")]
    GasPriceLow,
    #[error("Contract execution failed")]
    ContractExecution,
    #[error("Network connectivity issue")]
    NetworkConnectivity,
    #[error("Other retryable error")]
    OtherRetryable,
    #[error("Timeout")]
    Timeout,
    #[error("Receipt not found")]
    ReceiptNotFound,
    #[error("Gas wallet changed")]
    GasWalletChanged,
}
