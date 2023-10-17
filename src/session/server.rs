//! Server-[`Side`] implementation of the _session_.

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures_time::time::Duration;
use rand::RngCore;
use ssh_key::PrivateKey;
use ssh_packet::{arch::NameList, trans::KexInit, Id};

use super::Side;
use crate::{
    algorithm::{kex, key, Cipher, Compress, Hmac, Kex},
    stream::{Stream, TransportPair},
    Result,
};

/// A _server_-side session  configuration.
#[derive(Debug)]
pub struct Server {
    /// SSH [`Id`] for this _server_ session.
    pub id: Id,

    /// Timeout for sending and receiving packets.
    pub timeout: Duration,

    /// Server keys for key-exchange signature.
    pub keys: Vec<PrivateKey>,

    /// The algorithms enabled for this _server_ session.
    pub algorithms: Algorithms,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            id: Id::v2(
                concat!(
                    env!("CARGO_PKG_NAME"),
                    "@server:",
                    env!("CARGO_PKG_VERSION")
                ),
                None::<&str>,
            ),
            timeout: Duration::from_secs(3),
            keys: Default::default(),
            algorithms: Default::default(),
        }
    }
}

/// Algorithms for a _server_-side session.
#[derive(Debug)]
pub struct Algorithms {
    pub kexs: Vec<Kex>,

    pub ciphers: Vec<Cipher>,

    pub macs: Vec<Hmac>,

    pub compressions: Vec<Compress>,
}

impl Default for Algorithms {
    fn default() -> Self {
        Self {
            kexs: vec![Kex::Curve25519Sha256, Kex::Curve25519Sha256Libssh],
            ciphers: vec![
                Cipher::Aes256Ctr,
                Cipher::Aes192Ctr,
                Cipher::Aes128Ctr,
                Cipher::Aes256Cbc,
                Cipher::Aes192Cbc,
                Cipher::Aes128Cbc,
                Cipher::TDesCbc,
            ],
            macs: vec![
                Hmac::HmacSha512ETM,
                Hmac::HmacSha256ETM,
                Hmac::HmacSha512,
                Hmac::HmacSha256,
                Hmac::HmacSha1ETM,
                Hmac::HmacSha1,
            ],
            compressions: vec![Compress::ZlibOpenssh, Compress::Zlib, Compress::None],
        }
    }
}

#[async_trait]
impl Side for Server {
    fn id(&self) -> &Id {
        &self.id
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn kexinit(&self) -> KexInit {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        KexInit {
            cookie,
            kex_algorithms: NameList::new(&self.algorithms.kexs),
            server_host_key_algorithms: NameList::new(
                &self
                    .keys
                    .iter()
                    .map(|key| key.algorithm().to_string())
                    .collect::<Vec<_>>(),
            ),
            encryption_algorithms_client_to_server: NameList::new(&self.algorithms.ciphers),
            encryption_algorithms_server_to_client: NameList::new(&self.algorithms.ciphers),
            mac_algorithms_client_to_server: NameList::new(&self.algorithms.macs),
            mac_algorithms_server_to_client: NameList::new(&self.algorithms.macs),
            compression_algorithms_client_to_server: NameList::new(&self.algorithms.compressions),
            compression_algorithms_server_to_client: NameList::new(&self.algorithms.compressions),
            languages_client_to_server: NameList::default(),
            languages_server_to_client: NameList::default(),
            first_kex_packet_follows: false.into(),
        }
    }

    async fn exchange(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair> {
        let keyalg = key::negociate(&peerkexinit, &kexinit)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.algorithm() == keyalg)
            .expect("Did our KexInit lie to the client ?");

        kex::negociate(&peerkexinit, &kexinit)?
            .reply(stream, peer_id, self.id(), peerkexinit, kexinit, key)
            .await
    }
}
