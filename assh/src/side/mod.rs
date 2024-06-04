//! Session's [`Side`]s, either [`Client`] or [`Server`].

use futures::{AsyncBufRead, AsyncWrite, Future};
use futures_time::time::Duration;
use ssh_packet::{
    trans::{KexInit, NewKeys},
    Id,
};

use crate::{
    stream::{Stream, TransportPair},
    Result,
};

pub mod client;
use client::Client;

pub mod server;
use server::Server;

mod private {
    pub trait Sealed {}

    impl Sealed for super::Client {}
    impl Sealed for super::Server {}
}

/// A side of the SSH protocol, either [`Client`] or [`Server`].
pub trait Side: private::Sealed {
    /// Get the [`Id`] for this session.
    fn id(&self) -> &Id;

    // TODO: Is a timeout really needed in SSH2 ?
    /// Get the _timeout_ for this session.
    fn timeout(&self) -> Duration;

    /// Generate a [`KexInit`] message from the config.
    fn kexinit(&self) -> KexInit;

    /// Exchange the keys from the config.
    fn exchange(
        &self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> impl Future<Output = Result<TransportPair>>;

    /// Perform the key-exchange from this side.
    fn kex(
        &self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
        peer_id: &Id,
    ) -> impl Future<Output = Result<()>> {
        async move {
            tracing::debug!("Starting key-exchange procedure");

            let kexinit = self.kexinit();
            stream.send(&kexinit).await?;

            // TODO: Take care of `KexInit::first_kex_packet_follows` being true.

            let peerkexinit = stream.recv().await?.to::<KexInit>()?;

            let transport = self.exchange(stream, kexinit, peerkexinit, peer_id).await?;

            stream.send(&NewKeys).await?;
            stream.recv().await?.to::<NewKeys>()?;

            tracing::debug!(
                "Key exchange success, negociated algorithms:\nrx: {:?}\ntx: {:?}",
                transport.rx,
                transport.tx,
            );

            stream.with_transport(transport);

            Ok(())
        }
    }
}
