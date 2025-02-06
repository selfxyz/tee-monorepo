use std::num::TryFromIntError;
use std::time::{SystemTimeError, UNIX_EPOCH};
use std::{error::Error, time::SystemTime};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ethers::types::U256;
use oyster::attestation::{
    verify as verify_attestation, AttestationError, AttestationExpectations,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone)]
pub struct AppState {
    pub secp256k1_secret: secp256k1::SecretKey,
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
    pub secp256k1_public: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub timestamp: usize,
    pub verifier_secp256k1_public: String,
}

#[derive(Error)]
pub enum UserError {
    #[error("error while decoding attestation doc from hex")]
    AttestationDecode(#[source] hex::FromHexError),
    #[error("error while verifying attestation")]
    AttestationVerification(#[source] AttestationError),
    #[error("Message generation failed")]
    MessageGeneration(#[source] secp256k1::Error),
    #[error("invalid recovery id")]
    InvalidRecovery(#[source] TryFromIntError),
    #[error("system time error, clocks might be incorrect")]
    InvalidSystemTime(#[source] SystemTimeError),
}

impl From<UserError> for (StatusCode, String) {
    fn from(value: UserError) -> Self {
        use UserError::*;
        (
            match &value {
                AttestationDecode(_) => StatusCode::BAD_REQUEST,
                AttestationVerification(_) => StatusCode::UNAUTHORIZED,
                MessageGeneration(_) => StatusCode::INTERNAL_SERVER_ERROR,
                InvalidRecovery(_) => StatusCode::UNAUTHORIZED,
                InvalidSystemTime(_) => StatusCode::INTERNAL_SERVER_ERROR,
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

// keccak256(
//     abi.encode(
//         keccak256("EIP712Domain(string name,string version)"),
//         keccak256("marlin.oyster.AttestationVerifier"),
//         keccak256("1")
//     )
// )
const DOMAIN_SEPARATOR: [u8; 32] =
    hex_literal::hex!("0de834feb03c214f785e75b2828ffeceb322312d4487e2fb9640ca5fc32542c7");

// keccak256("Attestation(bytes enclavePubKey,bytes PCR0,bytes PCR1,bytes PCR2,uint256 timestampInMilliseconds)")
const ATTESTATION_TYPEHASH: [u8; 32] =
    hex_literal::hex!("6889df476ca38f3f4b417c17eb496682eb401b4f41a2259741a78acc481ea805");

fn compute_digest(
    enclave_pubkey: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    timestamp: usize,
) -> [u8; 32] {
    let mut encoded_struct = Vec::new();
    encoded_struct.reserve_exact(32 * 6);
    encoded_struct.extend_from_slice(&ATTESTATION_TYPEHASH);
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(enclave_pubkey));
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(pcr0));
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(pcr1));
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(pcr2));
    encoded_struct.resize(32 * 6, 0);
    U256::from(timestamp).to_big_endian(&mut encoded_struct[32 * 5..32 * 6]);

    let hash_struct = ethers::utils::keccak256(encoded_struct);

    let mut encoded_message = Vec::new();
    encoded_message.reserve_exact(2 + 32 * 2);
    encoded_message.extend_from_slice(&[0x19, 0x01]);
    encoded_message.extend_from_slice(&DOMAIN_SEPARATOR);
    encoded_message.extend_from_slice(&hash_struct);

    ethers::utils::keccak256(encoded_message)
}

fn verify(
    attestation: Vec<u8>,
    secret: &secp256k1::SecretKey,
    public: &[u8; 64],
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, String)> {
    let decoded = verify_attestation(
        attestation,
        AttestationExpectations {
            ..Default::default()
        },
    )
    .map_err(UserError::AttestationVerification)?;

    let digest = compute_digest(
        &decoded.public_key.as_slice(),
        &decoded.pcrs[0],
        &decoded.pcrs[1],
        &decoded.pcrs[2],
        decoded.timestamp,
    );

    let response_msg =
        secp256k1::Message::from_digest_slice(&digest).map_err(UserError::MessageGeneration)?;

    let secp = secp256k1::Secp256k1::new();
    let (recid, sig) = secp
        .sign_ecdsa_recoverable(&response_msg, secret)
        .serialize_compact();

    let sig = hex::encode(sig);
    let recid: u8 = i32::from(recid)
        .try_into()
        .map_err(UserError::InvalidRecovery)?;
    let recid = hex::encode([recid + 27]);

    Ok(VerifyAttestationResponse {
        signature: sig + &recid,
        secp256k1_public: hex::encode(decoded.public_key),
        pcr0: hex::encode(decoded.pcrs[0]),
        pcr1: hex::encode(decoded.pcrs[1]),
        pcr2: hex::encode(decoded.pcrs[2]),
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
        body.to_vec(),
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
        attestation,
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}
