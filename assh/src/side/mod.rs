//! Session's [`Side`]s, either [`Client`] or [`Server`].

use futures::Future;
use ssh_packet::{
    arch::id::Id,
    trans::{KexInit, NewKeys},
};

use crate::{
    Pipe, Result,
    stream::{Stream, TransportPair},
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
pub trait Side: private::Sealed + Send + Sync + Unpin + 'static {
    /// Get the [`Id`] for this session.
    fn id(&self) -> &Id;

    /// Generate a [`KexInit`] message from the config.
    fn kexinit(&self) -> KexInit<'static>;

    /// Exchange the keys from the config.
    fn exchange(
        &self,
        stream: &mut Stream<impl Pipe>,
        kexinit: &KexInit,
        peerkexinit: &KexInit,
        peer_id: &Id,
    ) -> impl Future<Output = Result<TransportPair>> + Send + Sync;

    /// Perform the key-exchange from this side.
    fn kex(
        &self,
        stream: &mut Stream<impl Pipe>,
        peer_id: &Id,
    ) -> impl Future<Output = Result<()>> + Send + Sync {
        async move {
            tracing::debug!("Starting key-exchange procedure");

            let kexinit = self.kexinit();
            stream.send(&kexinit).await?;

            // TODO: (compliance) Take care of `KexInit::first_kex_packet_follows` being true.

            let peerkexinit = stream.recv().await?.to::<KexInit>()?;

            let transport = self
                .exchange(stream, &kexinit, &peerkexinit, peer_id)
                .await?;

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
