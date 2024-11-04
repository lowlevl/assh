//! Server-[`Side`] implementation of the _session_.

use std::time::Duration;

use futures_time::time::Duration as Timeout;
use rand::RngCore;
use ssh_key::Algorithm;
use ssh_packet::{arch::NameList, trans::KexInit};

use super::Side;
use crate::{
    algorithm::{Cipher, Compress, Hmac, Kex, Negociate},
    stream::{Stream, TransportPair},
    Pipe, Result,
};

#[doc(no_inline)]
pub use ssh_key::PrivateKey;
#[doc(no_inline)]
pub use ssh_packet::Id;

/// A _server_-side session configuration.
#[derive(Debug, Clone)]
pub struct Server {
    /// [`Id`] for this _server_ session.
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
            timeout: Duration::from_secs(120),
            keys: Default::default(),
            algorithms: Default::default(),
        }
    }
}

/// Algorithms for a _server_-side session.
#[derive(Debug, Clone)]
pub struct Algorithms {
    /// Enabled algorithms for _key-exchange_.
    pub kexs: Vec<Kex>,

    /// Enabled algorithms for _encryption & decryption_.
    pub ciphers: Vec<Cipher>,

    /// Enabled algorithms for _hmac_.
    pub macs: Vec<Hmac>,

    /// Enabled algorithms for _compression_.
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
                Hmac::HmacMd5ETM,
                Hmac::HmacMd5,
            ],
            compressions: vec![Compress::ZlibOpenssh, Compress::Zlib, Compress::None],
        }
    }
}

impl Side for Server {
    fn id(&self) -> &Id {
        &self.id
    }

    fn timeout(&self) -> Timeout {
        self.timeout.into()
    }

    fn kexinit(&self) -> KexInit {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        KexInit {
            cookie,
            kex_algorithms: NameList::from_iter(&self.algorithms.kexs),
            server_host_key_algorithms: NameList::from_iter(
                self.keys.iter().map(PrivateKey::algorithm),
            ),
            encryption_algorithms_client_to_server: NameList::from_iter(&self.algorithms.ciphers),
            encryption_algorithms_server_to_client: NameList::from_iter(&self.algorithms.ciphers),
            mac_algorithms_client_to_server: NameList::from_iter(&self.algorithms.macs),
            mac_algorithms_server_to_client: NameList::from_iter(&self.algorithms.macs),
            compression_algorithms_client_to_server: NameList::from_iter(
                &self.algorithms.compressions,
            ),
            compression_algorithms_server_to_client: NameList::from_iter(
                &self.algorithms.compressions,
            ),
            languages_client_to_server: NameList::default(),
            languages_server_to_client: NameList::default(),
            first_kex_packet_follows: false.into(),
        }
    }

    async fn exchange(
        &self,
        stream: &mut Stream<impl Pipe>,
        kexinit: KexInit<'_>,
        peerkexinit: KexInit<'_>,
        peer_id: &Id,
    ) -> Result<TransportPair> {
        let alg = Algorithm::negociate(&peerkexinit, &kexinit)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.algorithm() == alg)
            .expect("Did our KexInit lie to the client ?");

        Kex::negociate(&peerkexinit, &kexinit)?
            .as_server(stream, peer_id, self.id(), peerkexinit, kexinit, key)
            .await
    }
}
