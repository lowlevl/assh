use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::{future::FutureExt, time::Duration};
use rand::RngCore;
use ssh_key::PrivateKey;
use ssh_packet::{
    arch::NameList,
    binrw::{meta::WriteEndian, BinWrite},
    trans::KexInit,
    Id, Message, Packet,
};
use strum::VariantNames;

use crate::{
    transport::{CompressAlg, EncryptAlg, HmacAlg, KexAlg, TransportPair},
    Error, Result,
};

// After 2 ^ 28 packets, initiate a rekey as recommended in the RFC.
const REKEY_AFTER: u32 = 0x10000000;

#[derive(Debug)]
pub struct Config {
    id: Id,
    keys: Vec<PrivateKey>,
    timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: Id::v2(
                concat!(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                None::<&str>,
            ),
            keys: vec![],
            timeout: Duration::from_secs(3),
        }
    }
}

pub struct Session<S> {
    config: Config,
    remote_id: Id,

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
            remote_id,
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
                    let packet = Packet::from_async_reader(stream, transport)
                        .timeout(self.config.timeout)
                        .await??;

                    let otherkexinit = packet.decrypt::<KexInit, _>(transport)?;

                    let kex: KexAlg = otherkexinit
                        .kex_algorithms
                        .preferred(&kexinit.kex_algorithms)
                        .ok_or(Error::NoCommonKex)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;

                    let mut transport = TransportPair::default();

                    transport.encrypt.rx = otherkexinit
                        .encryption_algorithms_client_to_server
                        .preferred(&kexinit.encryption_algorithms_client_to_server)
                        .ok_or(Error::NoCommonEncryption)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;
                    transport.encrypt.tx = otherkexinit
                        .encryption_algorithms_server_to_client
                        .preferred(&kexinit.encryption_algorithms_server_to_client)
                        .ok_or(Error::NoCommonEncryption)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;

                    transport.hmac.rx = otherkexinit
                        .mac_algorithms_client_to_server
                        .preferred(&kexinit.mac_algorithms_client_to_server)
                        .ok_or(Error::NoCommonHmac)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;
                    transport.hmac.tx = otherkexinit
                        .mac_algorithms_server_to_client
                        .preferred(&kexinit.mac_algorithms_server_to_client)
                        .ok_or(Error::NoCommonHmac)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;

                    transport.compress.rx = otherkexinit
                        .compression_algorithms_client_to_server
                        .preferred(&kexinit.compression_algorithms_client_to_server)
                        .ok_or(Error::NoCommonCompression)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;
                    transport.compress.tx = otherkexinit
                        .compression_algorithms_server_to_client
                        .preferred(&kexinit.compression_algorithms_server_to_client)
                        .ok_or(Error::NoCommonCompression)?
                        .parse()
                        .map_err(|_| Error::UnsupportedAlgorithm)?;
                }
                SessionState::Running { stream, transport } => {
                    // On first call to recv, the cipher will be `none`,
                    // initiate rekeying in this case,
                    // or if we sent a certain amount of packets.
                    if transport.encrypt.rx.is_none() || transport.hmac.seq > REKEY_AFTER {
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

                    let packet = Packet::from_async_reader(stream, transport)
                        .timeout(self.config.timeout)
                        .await??;

                    match packet.decrypt::<Message, _>(transport)? {
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

    pub async fn send<T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian>(
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
