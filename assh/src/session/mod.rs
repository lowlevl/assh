//! Session transport layer handling facilities.

use futures::{AsyncBufRead, AsyncWrite, AsyncWriteExt};
use futures_time::future::FutureExt;
use ssh_packet::{
    arch::StringUtf8,
    trans::{Debug, Disconnect, DisconnectReason, Ignore, KexInit, Unimplemented},
    Id, Packet, ToPacket,
};

use crate::{stream::Stream, Error, Result};

mod side;
pub use side::Side;

pub mod client;
pub mod server;

// TODO: Handle extension negotiation described in RFC8308

/// A session wrapping a `stream` to handle **key-exchange** and **[`SSH-TRANS`]** layer messages.
pub struct Session<I, S> {
    stream: Option<Stream<I>>,
    config: S,

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
            peer_id,
        })
    }

    /// Access the [`Id`] of the connected peer.
    pub fn peer_id(&self) -> &Id {
        &self.peer_id
    }

    /// Access initial exchange hash.
    pub fn session_id(&self) -> Option<&[u8]> {
        self.stream.as_ref().and_then(Stream::session_id)
    }

    /// Waits until the [`Session`] becomes readable,
    /// mainly to be used with [`Session::recv`] in [`futures::select`],
    /// since the `recv` method is **not cancel-safe**.
    pub async fn readable(&mut self) -> Result<()> {
        let Some(ref mut stream) = self.stream else {
            return Err(Error::Disconnected);
        };

        stream.fill_buf().await
    }

    /// Receive a _packet_ from the connected peer.
    ///
    /// # Cancel safety
    /// This method is **not cancel-safe**, if used within a [`futures::select`] call,
    /// some data may be partially received.
    pub async fn recv(&mut self) -> Result<Packet> {
        loop {
            let Some(ref mut stream) = self.stream else {
                break Err(Error::Disconnected);
            };

            if stream.is_rekeyable() || stream.peek().await?.to::<KexInit>().is_ok() {
                self.config.kex(stream, &self.peer_id).await?;

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
                break Ok(packet);
            }
        }
    }

    /// Send a _packet_ to the connected peer.
    pub async fn send(&mut self, message: &impl ToPacket) -> Result<()> {
        let Some(ref mut stream) = self.stream else {
            return Err(Error::Disconnected);
        };

        if stream.is_rekeyable()
            || (stream.is_readable().await? && stream.peek().await?.to::<KexInit>().is_ok())
        {
            self.config.kex(stream, &self.peer_id).await?;
        }

        stream.send(message).await
    }

    /// Send a _disconnect message_ to the peer and shutdown the session.
    pub async fn disconnect(
        &mut self,
        reason: DisconnectReason,
        description: impl Into<StringUtf8>,
    ) -> Result<()> {
        self.send(&Disconnect {
            reason,
            description: description.into(),
            language: Default::default(),
        })
        .await?;

        drop(self.stream.take());

        Ok(())
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
