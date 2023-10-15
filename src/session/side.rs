use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures_time::time::Duration;
use ssh_packet::{
    trans::{KexInit, NewKeys},
    Id,
};

use super::{client::Client, server::Server};
use crate::{stream::Stream, transport::TransportPair, Result};

mod private {
    pub trait Sealed {}

    impl Sealed for super::Client {}
    impl Sealed for super::Server {}
    impl<T: Sealed> Sealed for std::sync::Arc<T> {}
}

/// A side of the SSH protocol, either [`Client`] or [`Server`].
#[async_trait]
pub trait Side: private::Sealed + Send + Sync {
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
        tracing::debug!("Starting key-exchange procedure");

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

#[async_trait]
impl<T: Side> Side for std::sync::Arc<T> {
    fn id(&self) -> &Id {
        (**self).id()
    }

    fn timeout(&self) -> Duration {
        (**self).timeout()
    }

    fn kexinit(&self) -> KexInit {
        (**self).kexinit()
    }

    async fn exchange(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair> {
        (**self)
            .exchange(stream, kexinit, peerkexinit, peer_id)
            .await
    }
}
