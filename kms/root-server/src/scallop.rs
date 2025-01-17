use std::{
    net::SocketAddr,
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use oyster::{
    attestation::{self, AttestationExpectations, AWS_ROOT_KEY},
    scallop::{
        new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b, Key, ScallopAuthStore, ScallopAuther,
        ScallopStream,
    },
};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

#[derive(Clone, Default)]
pub struct AuthStore {}

pub type AuthStoreState = ([[u8; 48]; 3], Box<[u8]>);

impl ScallopAuthStore for AuthStore {
    type State = AuthStoreState;

    fn verify(&mut self, attestation: &[u8], _key: Key) -> Option<Self::State> {
        let Ok(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_millis() as usize)
        else {
            return None;
        };

        let Ok(decoded) = attestation::verify(
            attestation.to_vec(),
            AttestationExpectations {
                age: Some((300000, now)),
                root_public_key: Some(AWS_ROOT_KEY.to_vec()),
                // do not care about PCRs, will derive different keys for each set
                ..Default::default()
            },
        ) else {
            return None;
        };

        return Some((decoded.pcrs, decoded.user_data.into_boxed_slice()));
    }
}

#[derive(Clone)]
pub struct Auther {
    pub url: String,
}

impl ScallopAuther for Auther {
    type Error = anyhow::Error;

    async fn new_auth(&mut self) -> Result<Box<[u8]>> {
        let body = reqwest::get(&self.url)
            .await
            .context("failed to fetch attestation")?
            .bytes()
            .await
            .context("failed to read attestation")?;
        Ok(body.deref().into())
    }
}
