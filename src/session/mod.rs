//! Session and transport handling mechanics.

use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::future::FutureExt;
use ssh_packet::{
    binrw::{meta::WriteEndian, BinWrite},
    trans::{KexInit, NewKeys},
    Id, Message,
};

use crate::{algorithm::Kex, stream::Stream, transport::TransportPair, Error, Result};

mod config;
pub use config::Config;

/// A [`Session`] wrapping an [`AsyncRead`] + [`AsyncWrite`]
/// stream to handle **key exchange** and **[SSH-TRANS]** messages.
pub struct Session<S> {
    config: Config,
    peer_id: Id,

    disconnected: bool,
    stream: Stream<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    /// Create a new [`Session`] from a [`AsyncRead`] + [`AsyncWrite`] stream,
    /// and some configuration.
    pub async fn new(stream: S, config: Config) -> Result<Self> {
        let mut stream = BufReader::new(stream);

        config.id.to_async_writer(&mut stream).await?;
        let peer_id = Id::from_async_reader(&mut stream)
            .timeout(config.timeout)
            .await??;

        let stream = Stream::new(stream, TransportPair::default(), config.timeout);

        Ok(Self {
            config,
            peer_id,
            stream,
            disconnected: false,
        })
    }

    /// Get the [`Id`] of the connected peer.
    pub fn peer_id(&self) -> &Id {
        &self.peer_id
    }

    /// Receive the next [`Message`] in the `stream`, doing key-exchange if necessary.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            if self.disconnected {
                break Err(Error::Disconnected);
            }

            if self.stream.should_rekey() {
                self.kex(None).await?;
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
                Message::KexInit(kexinit) => self.kex(Some(kexinit)).await?,
                message => break Ok(message),
            }
        }
    }

    /// Send a [`Message`] to the `stream`, doing key-exchange if necessary.
    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian + std::fmt::Debug,
    {
        if self.disconnected {
            return Err(Error::Disconnected);
        }

        if let Some(kexinit) = self.stream.try_recv::<KexInit>().await? {
            self.kex(Some(kexinit)).await?
        } else if self.stream.should_rekey() {
            self.kex(None).await?
        }

        self.stream.send(message).await
    }

    async fn kex(&mut self, mut peerkexinit: Option<KexInit>) -> Result<()> {
        let kexinit = self.config.kexinit()?;
        self.stream.send(&kexinit).await?;

        let peerkexinit = match peerkexinit.take() {
            Some(peerkexinit) => peerkexinit,
            None => self.stream.recv().await?,
        };

        let kexalg = Kex::negociate(&peerkexinit, &kexinit)?;
        let keyalg = peerkexinit
            .server_host_key_algorithms
            .preferred_in(&kexinit.server_host_key_algorithms)
            .ok_or(Error::NoCommonKey)?
            .parse()
            .map_err(|_| Error::UnsupportedAlgorithm)?;

        let key = self
            .config
            .keys
            .iter()
            .find(|key| key.algorithm() == keyalg)
            .expect("Did our KexInit lie to the client ?");

        let negociated = kexalg
            .reply(
                &mut self.stream,
                &self.peer_id,
                &self.config.id,
                peerkexinit,
                kexinit,
                key,
            )
            .await?;

        self.stream.send(&NewKeys).await?;
        self.stream.recv::<NewKeys>().await?;

        tracing::debug!(
            "Key exchange success, negociated the following algorithms:\nrx: {:?}\ntx: {:?}",
            negociated.rx,
            negociated.tx,
        );

        self.stream.with_transport(negociated);

        Ok(())
    }
}
