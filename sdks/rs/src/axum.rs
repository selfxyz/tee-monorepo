use std::{
    net::SocketAddr,
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use tokio::net::{TcpListener, TcpStream};

use crate::scallop::{
    new_server_async_Noise_IX_25519_ChaChaPoly_BLAKE2b, Key, ScallopAuthStore, ScallopAuther,
    ScallopStream,
};

#[derive(Debug, thiserror::Error)]
pub enum AxumError {}

pub struct ScallopListener<AuthStore: ScallopAuthStore, Auther: ScallopAuther> {
    pub listener: TcpListener,
    pub secret: [u8; 32],
    pub auth_store: AuthStore,
    pub auther: Auther,
}

impl ScallopListener {
    async fn accept_impl(
        &mut self,
    ) -> Result<
        (
            <ScallopListener as Listener>::Io,
            <ScallopListener as Listener>::Addr,
        ),
        AxumError,
    > {
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

type ListenerIo = ScallopStream<TcpStream, AuthStoreState>;

impl Listener for ScallopListener {
    type Io = ListenerIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.accept_impl().await {
                Ok(res) => return res,
                Err(_) => {} // nothing, maybe log?
            }
        }
    }

    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[derive(Clone)]
pub struct ScallopState(pub Option<AuthStoreState>);

impl Connected<IncomingStream<'_, ScallopListener>> for ScallopState {
    fn connect_info(stream: IncomingStream<'_, ScallopListener>) -> Self {
        // is it possible to avoid a clone here?
        ScallopState(stream.io().state.clone())
    }
}
