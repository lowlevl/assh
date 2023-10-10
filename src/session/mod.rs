//! Session and transport handling mechanics.

use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::future::FutureExt;
use ssh_packet::{
    binrw::{meta::WriteEndian, BinWrite},
    trans::KexInit,
    Id, Message,
};

use crate::{stream::Stream, transport::TransportPair, Error, Result};

pub mod side;

/// A session wrapping an [`AsyncRead`] + [`AsyncWrite`]
/// stream to handle **key exchange** and **[`SSH-TRANS`]** messages.
pub struct Session<I, S> {
    config: S,
    stream: Stream<I>,

    peer_id: Id,
    disconnected: bool,
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send, S: side::Side> Session<I, S> {
    /// Create a new [`Session`] from a [`AsyncRead`] + [`AsyncWrite`] stream,
    /// and some configuration.
    pub async fn new(stream: I, config: S) -> Result<Self> {
        let mut stream = BufReader::new(stream);

        config.id().to_async_writer(&mut stream).await?;
        let peer_id = Id::from_async_reader(&mut stream)
            .timeout(config.timeout())
            .await??;

        let stream = Stream::new(stream, TransportPair::default(), config.timeout());

        Ok(Self {
            config,
            stream,

            peer_id,
            disconnected: false,
        })
    }

    /// Get the [`Id`] of the connected peer.
    pub fn peer_id(&self) -> &Id {
        &self.peer_id
    }

    /// Receive a [`Message`] from the `stream`.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            if self.disconnected {
                break Err(Error::Disconnected);
            }

            if self.stream.should_rekey() {
                self.config
                    .kex(&mut self.stream, None, &self.peer_id)
                    .await?;
            }

            match self.stream.recv().await? {
                Message::Disconnect(_) => {
                    self.disconnected = true;
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
                        .kex(&mut self.stream, Some(kexinit), &self.peer_id)
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
        if self.disconnected {
            return Err(Error::Disconnected);
        }

        if let Some(kexinit) = self.stream.try_recv::<KexInit>().await? {
            self.config
                .kex(&mut self.stream, Some(kexinit), &self.peer_id)
                .await?
        } else if self.stream.should_rekey() {
            self.config
                .kex(&mut self.stream, None, &self.peer_id)
                .await?
        }

        self.stream.send(message).await
    }
}
