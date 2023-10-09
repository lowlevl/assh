use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use ssh_packet::{
    trans::{KexInit, NewKeys},
    Id,
};

use crate::{stream::Stream, transport::TransportPair, Result};

/// A side of the SSH protocol.
#[async_trait]
pub trait Side {
    /// Configuration for this side of the protocol.
    type Config: Sync;

    /// Generate a [`KexInit`] message from the config.
    fn kexinit(config: &Self::Config) -> KexInit;

    /// Perform the key exchange from the config.
    async fn exchange(
        config: &Self::Config,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair>;

    /// Perform the key-exchange from this side.
    async fn kex(
        config: &Self::Config,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        mut peerkexinit: Option<KexInit>,
        peer_id: &Id,
    ) -> Result<()> {
        let kexinit = Self::kexinit(config);
        stream.send(&kexinit).await?;

        let peerkexinit = match peerkexinit.take() {
            Some(peerkexinit) => peerkexinit,
            None => stream.recv().await?,
        };

        let transport = Self::exchange(config, stream, kexinit, peerkexinit, peer_id).await?;

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
