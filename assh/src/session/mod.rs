//! Session management and transport handling mechanics.

use futures::{AsyncBufRead, AsyncWrite, AsyncWriteExt};
use futures_time::future::FutureExt;
use ssh_packet::{
    binrw::{
        meta::{ReadEndian, WriteEndian},
        BinRead, BinWrite,
    },
    trans::{Debug, Disconnect, Ignore, KexInit, Unimplemented},
    Id,
};

use crate::{Error, Result};

mod side;
pub use side::Side;

mod layer;
pub use layer::Layer;

pub mod client;
pub mod server;

pub use crate::stream::Stream;

/// A session wrapping a [`Stream`] to handle **key-exchange** and **[`SSH-TRANS`]** messages.
pub struct Session<I, S, L = ()> {
    stream: Option<Stream<I>>,
    config: S,
    layers: L,

    peer_id: Id,
}

impl<I, S> Session<I, S>
where
    I: AsyncBufRead + AsyncWrite + Unpin,
    S: Side,
{
    /// Create a new [`Session`] from a [`AsyncBufRead`] + [`AsyncWrite`] stream,
    /// and some configuration.
    pub async fn new(mut stream: I, config: S) -> Result<Self> {
        config.id().to_async_writer(&mut stream).await?;
        stream.flush().await?;

        let peer_id = Id::from_async_reader(&mut stream)
            .timeout(config.timeout())
            .await??;

        let stream = Stream::new(stream, config.timeout());

        tracing::debug!("Session started with peer `{peer_id}`");

        Ok(Self {
            stream: Some(stream),
            config,
            layers: (),
            peer_id,
        })
    }
}

impl<I, S, L> Session<I, S, L>
where
    I: AsyncBufRead + AsyncWrite + Unpin,
    S: Side,
    L: Layer<S>,
{
    /// Extend [`Session`]'s protocol handling capabilities with a [`Layer`].
    pub fn add_layer<N: Layer<S>>(self, layer: N) -> Session<I, S, impl Layer<S>> {
        let Self {
            stream,
            config,
            layers,
            peer_id,
        } = self;

        Session {
            stream,
            config,
            layers: (layers, layer),
            peer_id,
        }
    }

    /// Receive a _message_ from the connected peer.
    pub async fn recv<T>(&mut self) -> Result<T>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian + std::fmt::Debug,
    {
        loop {
            let Some(ref mut stream) = self.stream else {
                break Err(Error::Disconnected);
            };

            if stream.is_rekeyable() {
                self.config.kex(stream, None, &self.peer_id).await?;
                self.layers.on_kex(stream).await?;
            }

            self.layers.on_recv(stream).await?;

            if let Some(Disconnect {
                reason,
                description,
                ..
            }) = stream.try_recv().await?
            {
                drop(self.stream.take());

                tracing::warn!("Peer disconnected with `{reason:?}`: {}", &*description);
            } else if let Some(Ignore { data }) = stream.try_recv().await? {
                tracing::debug!("Received an 'ignore' message with length {}", data.len());
            } else if let Some(Debug { message, .. }) = stream.try_recv().await? {
                tracing::debug!("Received a 'debug' message: {}", &*message);
            } else if let Some(Unimplemented { seq }) = stream.try_recv().await? {
                tracing::debug!("Received a 'unimplemented' message about packet #{seq}",);
            } else if let Some(kexinit) = stream.try_recv().await? {
                self.config
                    .kex(stream, Some(kexinit), &self.peer_id)
                    .await?;
                self.layers.on_kex(stream).await?;
            } else {
                break stream.recv().await;
            }
        }
    }

    /// Send a _message_ to the connected peer.
    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        T: for<'w> BinWrite<Args<'w> = ()> + WriteEndian + std::fmt::Debug,
    {
        let Some(ref mut stream) = self.stream else {
            return Err(Error::Disconnected);
        };

        if stream.is_rekeyable() {
            self.config.kex(stream, None, &self.peer_id).await?;
            self.layers.on_kex(stream).await?;
        } else if stream.is_readable().await? {
            if let Some(kexinit) = stream.try_recv::<KexInit>().await? {
                self.config
                    .kex(stream, Some(kexinit), &self.peer_id)
                    .await?;
                self.layers.on_kex(stream).await?;
            }
        }

        stream.send(message).await
    }

    /// Access [`Id`] of the connected peer.
    pub fn peer_id(&self) -> &Id {
        &self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use async_std::net::TcpStream;

    use super::*;

    #[test]
    fn assert_session_is_send() {
        fn is_send<T: Send>() {}

        is_send::<Session<TcpStream, client::Client>>();
        is_send::<Session<TcpStream, server::Server>>();
    }

    #[test]
    fn assert_session_is_sync() {
        fn is_sync<T: Sync>() {}

        is_sync::<Session<TcpStream, client::Client>>();
        is_sync::<Session<TcpStream, server::Server>>();
    }
}
