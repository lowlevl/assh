use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::future::FutureExt;
use ssh_packet::{
    binrw::{meta::WriteEndian, BinWrite},
    trans::KexInit,
    Id, Message,
};

use super::Config;
use crate::{
    stream::Stream,
    transport::{Transport, TransportPair},
    Error, Result,
};

pub struct Session<S> {
    config: Config,
    peer_id: Id,

    state: SessionState<S>,
}

enum SessionState<S> {
    Kex {
        stream: Stream<S>,
        kexinit: Box<KexInit>,
    },
    Running {
        stream: Stream<S>,
    },
    Disconnected,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
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
            state: SessionState::Running { stream },
        })
    }

    pub fn peer_id(&self) -> &Id {
        &self.peer_id
    }

    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            match &mut self.state {
                SessionState::Disconnected => break Err(Error::Disconnected),
                SessionState::Kex { stream, kexinit } => {
                    let peerkexinit: KexInit = stream.recv().await?;

                    let (kexalg, keyalg, client_to_server, server_to_client) =
                        Transport::negociate(&peerkexinit, kexinit)?;
                    let transport = TransportPair {
                        rx: client_to_server,
                        tx: server_to_client,
                    };
                    let key = self
                        .config
                        .keys
                        .iter()
                        .find(|key| key.algorithm() == keyalg)
                        .ok_or(Error::NoCommonKey)?;

                    tracing::debug!("Negociated the following algorithms {transport:?}");

                    let secret = kexalg.reply(stream, key).await?;
                }
                SessionState::Running { stream } => {
                    // On first call to recv, the cipher will be `none`,
                    // initiate rekeying in this case,
                    // or if we sent a certain amount of packets.
                    if stream.needs_rekey() {
                        let kexinit = self.config.kexinit()?;
                        stream.send(&kexinit).await?;

                        replace_with::replace_with(
                            &mut self.state,
                            || SessionState::Disconnected,
                            |state| match state {
                                SessionState::Running { stream } => SessionState::Kex {
                                    stream,
                                    kexinit: kexinit.into(),
                                },
                                _ => state,
                            },
                        );

                        continue;
                    }

                    match stream.recv().await? {
                        Message::Disconnect(_) => {
                            self.state = SessionState::Disconnected;
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
                        message => break Ok(message),
                    }
                }
            }
        }
    }

    pub async fn send<T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian + std::fmt::Debug>(
        &mut self,
        message: &T,
    ) -> Result<()> {
        match &mut self.state {
            SessionState::Disconnected => Err(Error::Disconnected),
            SessionState::Running { stream, .. } | SessionState::Kex { stream, .. } => {
                stream.send(message).await
            }
        }
    }
}
