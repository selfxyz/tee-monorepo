use ethers::types::U256;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ServerlessError {
    #[error("Failed to decode log")]
    LogDecodeFailure,
    #[error("Job does not belong to the enclave")]
    JobDoesNotBelongToEnclave,
    #[error("Job is older than the maintained block states")]
    JobOlderThanMaintainedBlockStates,
    #[error("No Gateways Registered in cycle: {0}")]
    NoGatewaysRegisteredInCycle(u64),
    #[error("No Gateways avaialble in cycle: {0} for the Request Chain: {1}")]
    NoValidGatewaysForChain(u64, u64),
    #[error("No Subscription Job found for the subscription id: {0}")]
    NoSubscriptionJobFound(U256),

    #[cfg(test)]
    #[error("Invalid topic")]
    InvalidTopic,

    #[cfg(test)]
    #[error("Empty Topics")]
    EmptyTopics,

    #[cfg(test)]
    #[error("Empty Topic 0")]
    EmptyTopic0,
}
