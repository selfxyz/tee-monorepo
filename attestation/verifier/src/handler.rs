use std::error::Error;
use std::num::TryFromIntError;

use alloy::{
    dyn_abi::Eip712Domain,
    primitives::U256,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
    sol_types::{eip712_domain, SolStruct},
};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use oyster::attestation::{
    verify as verify_attestation, AttestationError, AttestationExpectations, AWS_ROOT_KEY,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone)]
pub struct AppState {
    pub secp256k1_secret: PrivateKeySigner,
    pub secp256k1_public: [u8; 64],
}

#[derive(Deserialize, Serialize)]
struct RawAttestation {
    attestation: String,
}

#[derive(Deserialize, Serialize)]
struct HexAttestation {
    attestation: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyAttestationResponse {
    pub signature: String,
    pub public_key: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub user_data: String,
    pub timestamp: usize,
    pub verifier_secp256k1_public: String,
}

#[derive(Error)]
pub enum UserError {
    #[error("error while decoding attestation doc from hex")]
    AttestationDecode(#[source] hex::FromHexError),
    #[error("error while verifying attestation")]
    AttestationVerification(#[source] AttestationError),
    #[error("Signature generation failed")]
    SignatureGeneration(#[source] alloy::signers::Error),
    #[error("invalid recovery id")]
    InvalidRecovery(#[source] TryFromIntError),
}

impl From<UserError> for (StatusCode, String) {
    fn from(value: UserError) -> Self {
        use UserError::*;
        (
            match &value {
                AttestationDecode(_) => StatusCode::BAD_REQUEST,
                AttestationVerification(_) => StatusCode::UNAUTHORIZED,
                SignatureGeneration(_) => StatusCode::INTERNAL_SERVER_ERROR,
                InvalidRecovery(_) => StatusCode::UNAUTHORIZED,
            },
            format!("{:?}", value),
        )
    }
}

impl std::fmt::Debug for UserError {
    // pretty print like anyhow
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)?;

        if self.source().is_some() {
            writeln!(f, "\n\nCaused by:")?;
        }

        let mut err: &dyn Error = self;
        loop {
            let Some(source) = err.source() else { break };
            writeln!(f, "\t{}", source)?;

            err = source;
        }

        Ok(())
    }
}

const DOMAIN: Eip712Domain = eip712_domain! {
    name: "marlin.oyster.AttestationVerifier",
    version: "1",
};

sol! {
    struct Attestation {
        bytes enclavePubKey;
        bytes PCR0;
        bytes PCR1;
        bytes PCR2;
        uint256 timestampInMilliseconds;
    }
}

fn compute_signature(
    enclave_pubkey: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    timestamp: usize,
    signer: &PrivateKeySigner,
) -> Result<[u8; 65], UserError> {
    let attestation = Attestation {
        enclavePubKey: enclave_pubkey.to_owned().into(),
        PCR0: pcr0.to_owned().into(),
        PCR1: pcr1.to_owned().into(),
        PCR2: pcr2.to_owned().into(),
        timestampInMilliseconds: U256::from(timestamp),
    };
    let hash = attestation.eip712_signing_hash(&DOMAIN);
    let signature = signer
        .sign_hash_sync(&hash)
        .map_err(UserError::SignatureGeneration)?
        .as_bytes();

    Ok(signature)
}

fn verify(
    attestation: &[u8],
    signer: &PrivateKeySigner,
    public: &[u8; 64],
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    let decoded = verify_attestation(
        attestation,
        AttestationExpectations {
            root_public_key: Some(&AWS_ROOT_KEY),
            ..Default::default()
        },
    )
    .map_err(UserError::AttestationVerification)?;

    let signature = compute_signature(
        &decoded.public_key.as_ref(),
        &decoded.pcrs[0],
        &decoded.pcrs[1],
        &decoded.pcrs[2],
        decoded.timestamp,
        signer,
    )?;

    Ok(VerifyAttestationResponse {
        signature: hex::encode(signature),
        public_key: hex::encode(decoded.public_key),
        pcr0: hex::encode(decoded.pcrs[0]),
        pcr1: hex::encode(decoded.pcrs[1]),
        pcr2: hex::encode(decoded.pcrs[2]),
        user_data: hex::encode(decoded.user_data),
        timestamp: decoded.timestamp,
        verifier_secp256k1_public: hex::encode(public),
    }
    .into())
}

pub async fn verify_raw(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    verify(
        &body.to_vec(),
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}

pub async fn verify_hex(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    let attestation = hex::decode(&body).map_err(UserError::AttestationDecode)?;

    verify(
        &attestation,
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}
