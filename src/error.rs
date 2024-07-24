use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ServerlessError {
    #[error("Failed to decode log")]
    LogDecodingError,
    #[error("Job does not belong to the enclave")]
    JobNotBelongToEnclave,
    #[error("Job is older than the maintained block states")]
    JobOlderThanMaintainedBlockStates,
    #[error("No Gateways Registered")]
    NoGatewaysRegistered,
    #[error("No Gateways avaialble for the Request Chain: {0}")]
    NoGatewaysAvailableForRequestChain(u64),
}
