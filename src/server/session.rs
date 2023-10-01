use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::future::FutureExt;
use rand::RngCore;
use ssh_packet::{
    arch::NameList,
    binrw::{meta::WriteEndian, BinWrite},
    trans::KexInit,
    Id, Message, Packet,
};
use strum::VariantNames;

use super::Config;
use crate::{
    transport::{CompressAlg, EncryptAlg, HmacAlg, KexAlg, Transport, TransportPair},
    Error, Result,
};

/// After 2 ^ 28 packets, initiate a rekey as recommended in the RFC.
const REKEY_AFTER: u32 = 0x10000000;

// TODO: Rekey after 1GiB

pub struct Session<S> {
    config: Config,
    peer_id: Id,

    state: SessionState<S>,
}

enum SessionState<S> {
    Kex {
        stream: BufReader<S>,
        transport: TransportPair,
        kexinit: Box<KexInit>,
    },
    Running {
        stream: BufReader<S>,
        transport: TransportPair,
    },
    Disconnected,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    pub async fn new(stream: S, config: Config) -> Result<Self> {
        let mut stream = BufReader::new(stream);

        config.id.to_async_writer(&mut stream).await?;
        let remote_id = Id::from_async_reader(&mut stream)
            .timeout(config.timeout)
            .await??;

        Ok(Self {
            config,
            peer_id: remote_id,
            state: SessionState::Running {
                stream,
                transport: TransportPair::default(),
            },
        })
    }

    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            match &mut self.state {
                SessionState::Disconnected => break Err(Error::Disconnected),
                SessionState::Kex {
                    stream,
                    transport,
                    kexinit,
                } => {
                    let peerkexinit: KexInit = Packet::from_async_reader(stream, transport)
                        .timeout(self.config.timeout)
                        .await??
                        .decrypt(transport)?;

                    let (kexalg, client_to_server, server_to_client) =
                        Transport::negociate(&peerkexinit, kexinit)?;
                    let newtransport = TransportPair {
                        rx: client_to_server,
                        tx: server_to_client,
                    };

                    tracing::debug!("Negociated the following algorithms {transport:?}");

                    let secret = kexalg.reply(stream, transport, self.config.timeout).await?;
                }
                SessionState::Running { stream, transport } => {
                    // On first call to recv, the cipher will be `none`,
                    // initiate rekeying in this case,
                    // or if we sent a certain amount of packets.
                    if transport.tx.encrypt.is_none() || transport.tx.seq > REKEY_AFTER {
                        let kexinit = self.kexinit();
                        self.send(&kexinit).await?;

                        replace_with::replace_with(
                            &mut self.state,
                            || SessionState::Disconnected,
                            |state| match state {
                                SessionState::Running {
                                    stream,
                                    transport: cipher,
                                } => SessionState::Kex {
                                    stream,
                                    transport: cipher,
                                    kexinit: kexinit.into(),
                                },
                                _ => state,
                            },
                        );

                        continue;
                    }

                    let message: Message = Packet::from_async_reader(stream, transport)
                        .timeout(self.config.timeout)
                        .await??
                        .decrypt(transport)?;

                    match message {
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
            SessionState::Running {
                stream, transport, ..
            }
            | SessionState::Kex {
                stream, transport, ..
            } => {
                let packet = Packet::encrypt(message, transport)?;
                tracing::trace!(
                    "Sending (payload: {}, padding: {}, size: {}) {message:?}",
                    packet.payload.len(),
                    packet.padding.len(),
                    packet.size()
                );

                Ok(packet.to_async_writer(stream).await?)
            }
        }
    }

    fn kexinit(&self) -> KexInit {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        KexInit {
            cookie,
            kex_algorithms: NameList::new(KexAlg::VARIANTS),
            server_host_key_algorithms: NameList::new(
                &self
                    .config
                    .keys
                    .iter()
                    .map(|key| key.algorithm().to_string())
                    .collect::<Vec<_>>(),
            ),
            encryption_algorithms_client_to_server: NameList::new(EncryptAlg::VARIANTS),
            encryption_algorithms_server_to_client: NameList::new(EncryptAlg::VARIANTS),
            mac_algorithms_client_to_server: NameList::new(HmacAlg::VARIANTS),
            mac_algorithms_server_to_client: NameList::new(HmacAlg::VARIANTS),
            compression_algorithms_client_to_server: NameList::new(CompressAlg::VARIANTS),
            compression_algorithms_server_to_client: NameList::new(CompressAlg::VARIANTS),
            languages_client_to_server: NameList::default(),
            languages_server_to_client: NameList::default(),
            first_kex_packet_follows: false.into(),
        }
    }
}
