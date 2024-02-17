//! Session and transport handling mechanics.

use futures::{io::BufReader, AsyncRead, AsyncWrite, AsyncWriteExt};
use futures_time::future::FutureExt;
use ssh_packet::{
    binrw::{meta::WriteEndian, BinWrite},
    trans::KexInit,
    Message, SshId,
};

use crate::{stream::Stream, Error, Result};

mod side;
pub use side::Side;

pub mod client;
pub mod server;

/// A session wrapping an [`AsyncRead`] + [`AsyncWrite`]
/// stream to handle **key exchange** and **[`SSH-TRANS`]** messages.
pub struct Session<I, S> {
    stream: Option<Stream<I>>,
    config: S,

    peer_id: SshId,
}

impl<I, S> Session<I, S>
where
    I: AsyncRead + AsyncWrite + Unpin + Send,
    S: side::Side,
{
    /// Create a new [`Session`] from a [`AsyncRead`] + [`AsyncWrite`] stream,
    /// and some configuration.
    pub async fn new(stream: I, config: S) -> Result<Self> {
        let mut stream = BufReader::new(stream);

        config.id().to_async_writer(&mut stream).await?;
        stream.flush().await?;

        let peer_id = SshId::from_async_reader(&mut stream)
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

    /// Get the [`SshId`] of the connected peer.
    pub fn peer_id(&self) -> &SshId {
        &self.peer_id
    }

    /// Receive a [`Message`] from the `stream`.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            let Some(ref mut stream) = self.stream else {
                break Err(Error::Disconnected);
            };

            if stream.rekeyable() {
                self.config.kex(stream, None, &self.peer_id).await?;
            }

            match stream.recv().await? {
                Message::Disconnect(_) => {
                    drop(self.stream.take());
                }
                Message::Ignore(_) => {
                    tracing::debug!("Received an 'ignore' message");
                }
                Message::Debug(message) => {
                    tracing::debug!("Received a 'debug' message: {}", &*message.message);
                }
                Message::Unimplemented(message) => {
                    tracing::debug!(
                        "Received a 'unimplemented' message about packet #{}",
                        message.seq
                    );
                }
                Message::KexInit(kexinit) => {
                    self.config
                        .kex(stream, Some(kexinit), &self.peer_id)
                        .await?
                }
                message => break Ok(message),
            }
        }
    }

    /// Send a [`Message`] to the `stream`.
    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian + std::fmt::Debug,
    {
        let Some(ref mut stream) = self.stream else {
            return Err(Error::Disconnected);
        };

        if let Some(kexinit) = stream.try_recv::<KexInit>().await? {
            self.config
                .kex(stream, Some(kexinit), &self.peer_id)
                .await?
        } else if stream.rekeyable() {
            self.config.kex(stream, None, &self.peer_id).await?
        }

        stream.send(message).await
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
