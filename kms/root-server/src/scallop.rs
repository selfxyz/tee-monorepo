use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::serve::Listener;
use oyster::scallop::{
    new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b, Key, ScallopAuthStore, ScallopAuther,
    ScallopStream,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

#[derive(Clone)]
pub struct AuthStore {}

impl ScallopAuthStore for AuthStore {
    fn verify(&mut self, attestation: &[u8], key: Key) -> bool {
        todo!()
    }
}

#[derive(Clone)]
pub struct Auther {
    pub url: String,
}

impl ScallopAuther for Auther {
    type Error = anyhow::Error;

    async fn new_auth(&mut self) -> Result<Box<[u8]>> {
        todo!()
    }
}

pub struct ScallopListener {
    pub listener: TcpListener,
    pub secret: [u8; 32],
    pub auth_store: AuthStore,
    pub auther: Auther,
}

impl ScallopListener {
    async fn accept_impl(
        &mut self,
    ) -> Result<(
        <ScallopListener as Listener>::Io,
        <ScallopListener as Listener>::Addr,
    )> {
        let (stream, addr) = self
            .listener
            .accept()
            .await
            .context("failed to accept conns")?;
        let stream = new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b(
            stream,
            &self.secret,
            Some(self.auth_store.clone()),
            Some(self.auther.clone()),
        )
        .await
        .context("failed to scallop")?;

        Ok((stream, addr))
    }
}

impl Listener for ScallopListener {
    type Io = ScallopStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.accept_impl().await {
                Ok(res) => return res,
                Err(e) => error!("{e:?}"),
            }
        }
    }

    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
