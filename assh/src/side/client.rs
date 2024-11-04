//! Client-[`Side`] implementation of the _session_.

use std::time::Duration;

use futures_time::time::Duration as Timeout;
use rand::RngCore;
use ssh_packet::{arch::NameList, trans::KexInit};

use super::Side;
use crate::{
    algorithm::{Cipher, Compress, Hmac, Kex, Key, Negociate},
    stream::{Stream, TransportPair},
    Pipe, Result,
};

#[doc(no_inline)]
pub use ssh_packet::Id;

// TODO: (compliance) Hostkey verification in client key-exchange.

/// A _client_-side session configuration.
#[derive(Debug, Clone)]
pub struct Client {
    /// [`Id`] for this _client_ session.
    pub id: Id,

    /// Timeout for sending and receiving packets.
    pub timeout: Duration,

    /// The algorithms enabled for this _client_ session.
    pub algorithms: Algorithms,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            id: Id::v2(
                concat!(
                    env!("CARGO_PKG_NAME"),
                    "@client:",
                    env!("CARGO_PKG_VERSION")
                ),
                None::<&str>,
            ),
            timeout: Duration::from_secs(120),
            algorithms: Default::default(),
        }
    }
}

/// Algorithms for a _client_-side session.
#[derive(Debug, Clone)]
pub struct Algorithms {
    /// Enabled algorithms for _key-exchange_.
    pub kexs: Vec<Kex>,

    /// Enabled algorithms for _server key signature_.
    pub keys: Vec<Key>,

    /// Enabled algorithms for _encryption & decryption_.
    pub ciphers: Vec<Cipher>,

    /// Enabled algorithms for _hmac_.
    pub macs: Vec<Hmac>,

    /// Enabled algorithms for _compression_.
    pub compressions: Vec<Compress>,
}

impl Default for Algorithms {
    fn default() -> Self {
        let super::server::Algorithms {
            kexs,
            ciphers,
            macs,
            compressions,
        } = Default::default();

        Self {
            kexs,
            keys: vec![
                Key::Ed25519,
                Key::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384,
                },
                Key::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256,
                },
                Key::Rsa {
                    hash: Some(ssh_key::HashAlg::Sha512),
                },
                Key::Rsa {
                    hash: Some(ssh_key::HashAlg::Sha256),
                },
                Key::Rsa { hash: None },
                Key::Dsa,
            ],
            ciphers,
            macs,
            compressions,
        }
    }
}

impl Side for Client {
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
            server_host_key_algorithms: NameList::from_iter(&self.algorithms.keys),
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
            languages_client_to_server: Default::default(),
            languages_server_to_client: Default::default(),
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
        Kex::negociate(&kexinit, &peerkexinit)?
            .as_client(stream, self.id(), peer_id, kexinit, peerkexinit)
            .await
    }
}
