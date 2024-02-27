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

pub mod client;
pub mod server;

pub use crate::stream::Stream;

use crate::layer::{Action, Layer};

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
        T: for<'a> BinRead<Args<'a> = ()> + ReadEndian,
    {
        loop {
            let Some(ref mut stream) = self.stream else {
                break Err(Error::Disconnected);
            };

            if stream.is_rekeyable() || stream.peek().await?.to::<KexInit>().is_ok() {
                self.config.kex(stream, &self.peer_id).await?;
                self.layers.on_kex(stream).await?;

                continue;
            }

            let packet = stream.recv().await?;

            if let Ok(Disconnect {
                reason,
                description,
                ..
            }) = packet.to()
            {
                tracing::warn!("Peer disconnected with `{reason:?}`: {}", &*description);

                drop(self.stream.take());
            } else if let Ok(Ignore { data }) = packet.to() {
                tracing::debug!("Received an 'ignore' message with length {}", data.len());
            } else if let Ok(Unimplemented { seq }) = packet.to() {
                tracing::debug!("Received an 'unimplemented' message about packet #{seq}",);
            } else if let Ok(Debug { message, .. }) = packet.to() {
                tracing::debug!("Received a 'debug' message: {}", &*message);
            } else {
                match self.layers.on_recv(stream, packet).await? {
                    Action::Next => continue,
                    Action::Disconnect {
                        reason,
                        description,
                    } => {
                        stream
                            .send(&Disconnect {
                                reason,
                                description: description.into(),
                                language: Default::default(),
                            })
                            .await?;

                        drop(self.stream.take());
                    }
                    Action::Forward(packet) => break packet.to().map_err(Into::into),
                }
            }
        }
    }

    /// Send a _message_ to the connected peer.
    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian,
    {
        let Some(ref mut stream) = self.stream else {
            return Err(Error::Disconnected);
        };

        if stream.is_rekeyable()
            || (stream.is_readable().await? && stream.peek().await?.to::<KexInit>().is_ok())
        {
            self.config.kex(stream, &self.peer_id).await?;
            self.layers.on_kex(stream).await?;
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
