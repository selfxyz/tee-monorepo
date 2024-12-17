mod attestation;
pub mod scallop;

pub use attestation::{
    decode_attestation, get_attestation_doc, verify, verify_custom_root, verify_with_timestamp,
    AttestationError,
};
