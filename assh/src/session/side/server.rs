//! Server-[`Side`] implementation of the _session_.

use ssh_packet::{
    arch::{NameList, id::Id},
    trans::KexInit,
};

use super::Side;
use crate::{
    Result,
    core::algorithm::{
        Negociate,
        cipher::Cipher,
        compress::Compress,
        hmac::Hmac,
        kex::{self, Kex},
        key,
    },
};

#[doc(no_inline)]
pub use ssh_key::PrivateKey;

/// A _server_-side session configuration.
#[derive(Debug, Clone)]
pub struct Server {
    /// [`Id`] for this _server_ session.
    pub id: Id,

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
                    "@",
                    env!("CARGO_PKG_VERSION"),
                    "+server"
                ),
                None::<&str>,
            ),
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

    fn kexinit(&self) -> KexInit<'static> {
        KexInit {
            cookie: rand::random(),
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

    type Kex = kex::Server;
    fn kex(
        &self,
        kexinit: kex::KexInit<'static>,
        peerkexinit: kex::KexInit<'static>,
        peer_id: Id,
    ) -> Result<Self::Kex> {
        let kex = Kex::negociate(&peerkexinit, &kexinit)?;

        let alg = key::Key::negociate(&peerkexinit, &kexinit)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.algorithm() == alg)
            .expect("no suitable private key for server key algorithm");

        let (client, server) =
            kex::Meta::new((peer_id, peerkexinit), (self.id().clone(), kexinit))?;

        Ok(kex.as_server(client, server, key.clone()))
    }
}
