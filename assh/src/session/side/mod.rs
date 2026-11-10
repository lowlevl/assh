//! Session's [`Side`]s, either [`Client`] or [`Server`].

use futures::SinkExt;
use ssh_packet::{
    IntoPacket,
    trans::{KexInit, NewKeys},
};

use crate::{
    Pipe, Result,
    core::{
        Core,
        algorithm::kex::{self, Exchange},
    },
};

#[doc(no_inline)]
pub use ssh_packet::arch::id::Id;

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

    /// Key-exchange state for this [`Side`].
    type Kex: kex::Exchange;

    /// Init a key-exchange state from the config.
    fn kex(
        &self,
        kexinit: KexInit<'static>,
        peerkexinit: KexInit<'static>,
        peer_id: Id,
    ) -> Result<Self::Kex>;

    /// Perform the key-exchange from this side.
    fn exchange(
        &self,
        core: &mut Core<impl Pipe>,
        peer_id: &Id,
    ) -> impl Future<Output = Result<()>> + Send + Sync {
        async move {
            tracing::debug!("Starting key-exchange procedure");

            let kexinit = self.kexinit();
            core.send(&kexinit.into_packet()).await?;

            // TODO: (compliance) Take care of `KexInit::first_kex_packet_follows` being true.

            let peerkex = core.recv().await?.to::<KexInit>()?;

            let mut kex = self.kex(kexinit, peerkex, peer_id.clone())?;
            let (rx, tx) =
                futures::future::poll_fn::<Result<_>, _>(|cx| kex.poll(cx, core)).await?;

            core.send(&NewKeys.into_packet()).await?;
            core.recv().await?.to::<NewKeys>()?;

            tracing::debug!("Key exchange success, negociated algorithms:\nrx: {rx:?}\ntx: {tx:?}",);

            core.set_transport(rx, tx);

            Ok(())
        }
    }
}
