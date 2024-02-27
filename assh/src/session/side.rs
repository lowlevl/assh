use futures::{AsyncBufRead, AsyncWrite, Future};
use futures_time::time::Duration;
use ssh_packet::{
    trans::{KexInit, NewKeys},
    Id,
};

use super::{client::Client, server::Server};
use crate::{
    stream::{Stream, TransportPair},
    Result,
};

mod private {
    pub trait Sealed {}

    impl Sealed for super::Client {}
    impl Sealed for super::Server {}
    impl<T: Sealed> Sealed for std::sync::Arc<T> {}
}

/// A side of the SSH protocol, either [`Client`] or [`Server`].
pub trait Side: private::Sealed {
    /// Get the [`Id`] for this session.
    fn id(&self) -> &Id;

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
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair> {
        (**self)
            .exchange(stream, kexinit, peerkexinit, peer_id)
            .await
    }
}
