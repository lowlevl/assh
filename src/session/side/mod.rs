//! The specializations of the session for the _client_ or _server_ side of the protocol.

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures_time::time::Duration;
use ssh_packet::{
    trans::{KexInit, NewKeys},
    Id,
};

mod client;
pub use client::Client;

mod server;
pub use server::Server;

use crate::{stream::Stream, transport::TransportPair, Result};

mod private {
    pub trait Sealed {}

    impl Sealed for super::Client {}
    impl Sealed for super::Server {}
}

/// A side of the SSH protocol, either [`Client`] or [`Server`].
#[async_trait]
pub trait Side: private::Sealed {
    /// Get the [`Id`] for this session.
    fn id(&self) -> &Id;

    /// Get the _timeout_ for this session.
    fn timeout(&self) -> Duration;

    /// Generate a [`KexInit`] message from the config.
    fn kexinit(&self) -> KexInit;

    /// Exchange the keys from the config.
    async fn exchange(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair>;

    /// Perform the key-exchange from this side.
    async fn kex(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        mut peerkexinit: Option<KexInit>,
        peer_id: &Id,
    ) -> Result<()> {
        let kexinit = self.kexinit();
        stream.send(&kexinit).await?;

        let peerkexinit = match peerkexinit.take() {
            Some(peerkexinit) => peerkexinit,
            None => stream.recv().await?,
        };

        let transport = self.exchange(stream, kexinit, peerkexinit, peer_id).await?;

        stream.send(&NewKeys).await?;
        stream.recv::<NewKeys>().await?;

        tracing::debug!(
            "Key exchange success, negociated algorithms:\nrx: {:?}\ntx: {:?}",
            transport.rx,
            transport.tx,
        );

        stream.with_transport(transport);

        Ok(())
    }
}
