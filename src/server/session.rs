use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::future::FutureExt;
use ssh_packet::{
    binrw::{meta::WriteEndian, BinWrite},
    trans::{KexInit, NewKeys},
    Id, Message,
};

use super::Config;
use crate::{algorithm::Kex, stream::Stream, transport::TransportPair, Error, Result};

pub struct Session<S> {
    config: Config,
    peer_id: Id,

    state: SessionState<S>,
}

enum SessionState<S> {
    Kex {
        stream: Stream<S>,
        peerkexinit: Option<Box<KexInit>>,
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
                SessionState::Kex {
                    stream,
                    peerkexinit,
                } => {
                    let kexinit = self.config.kexinit()?;
                    stream.send(&kexinit).await?;

                    let peerkexinit = match peerkexinit.take() {
                        Some(peerkexinit) => *peerkexinit,
                        None => stream.recv().await?,
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
                            stream,
                            &self.peer_id,
                            &self.config.id,
                            peerkexinit,
                            kexinit,
                            key,
                        )
                        .await?;

                    stream.send(&NewKeys).await?;
                    stream.recv::<NewKeys>().await?;

                    tracing::debug!(
                        "Negociated the following algorithms:\nrx: {:?}\ntx: {:?}",
                        negociated.talg,
                        negociated.ralg
                    );

                    stream.with_transport(negociated);

                    replace_with::replace_with(
                        &mut self.state,
                        || SessionState::Disconnected,
                        |state| match state {
                            SessionState::Kex { stream, .. } => SessionState::Running { stream },
                            _ => state,
                        },
                    );
                }
                SessionState::Running { stream } => {
                    // On first call to recv, the cipher will be `none`,
                    // initiate rekeying in this case,
                    // or if we sent a certain amount of packets.
                    if stream.should_rekey() {
                        replace_with::replace_with(
                            &mut self.state,
                            || SessionState::Disconnected,
                            |state| match state {
                                SessionState::Running { stream } => SessionState::Kex {
                                    stream,
                                    peerkexinit: None,
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
                        Message::KexInit(kexinit) => {
                            replace_with::replace_with(
                                &mut self.state,
                                || SessionState::Disconnected,
                                |state| match state {
                                    SessionState::Running { stream } => SessionState::Kex {
                                        stream,
                                        peerkexinit: Some(kexinit.into()),
                                    },
                                    _ => state,
                                },
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
        // TODO: Handle KEX also there
        match &mut self.state {
            SessionState::Disconnected => Err(Error::Disconnected),
            SessionState::Running { stream, .. } | SessionState::Kex { stream, .. } => {
                stream.send(message).await
            }
        }
    }
}
