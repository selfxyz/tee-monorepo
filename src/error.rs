use ethers::abi::Error as AbiError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ServerlessError {
    #[error("failed to decode log: {0}")]
    LogDecodingError(#[from] AbiError),
    #[error("Job does not belong to the enclave")]
    JobNotBelongToEnclave,
    #[error("Job is older than the maintained block states")]
    JobOlderThanMaintainedBlockStates,
    #[error("No Gateways Registered")]
    NoGatewaysRegistered,
    #[error("No Gateways avaialble for the Request Chain: {0}")]
    NoGatewaysAvailableForRequestChain(u64),
}
