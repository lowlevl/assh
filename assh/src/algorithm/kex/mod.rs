use ssh_key::PrivateKey;
use ssh_packet::{arch::NameList, trans::KexInit, Id};
use strum::{AsRefStr, EnumString};

use crate::{
    side::{client::Client, server::Server},
    stream::{Keys, Stream, Transport, TransportPair},
    Error, Pipe, Result,
};

use super::{Cipher, Compress, Hmac, Negociate};

mod curve25519;

impl Negociate for Kex {
    const ERR: Error = Error::NoCommonKex;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.kex_algorithms
    }
}

// TODO: (feature) Implement the following legacy key-exchange methods (`diffie-hellman-group14-sha256`, `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1`).

/// SSH key-exchange algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, EnumString, AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub enum Kex {
    /// Curve25519 ECDH with sha-2-256 digest.
    Curve25519Sha256,

    /// Curve25519 ECDH with sha-2-256 digest (pre-RFC 8731).
    #[strum(serialize = "curve25519-sha256@libssh.org")]
    Curve25519Sha256Libssh,
    //
    // DiffieHellmanGroup14Sha256,
    //
    // DiffieHellmanGroup14Sha1,
    //
    // DiffieHellmanGroup1Sha1,
}

impl Kex {
    pub(crate) async fn as_client(
        &self,
        stream: &mut Stream<impl Pipe>,
        v_c: &Id,
        v_s: &Id,
        i_c: KexInit<'_>,
        i_s: KexInit<'_>,
    ) -> Result<TransportPair> {
        let (client_hmac, server_hmac) = (
            <Hmac as Negociate<Client>>::negociate(&i_c, &i_s)?,
            <Hmac as Negociate<Server>>::negociate(&i_c, &i_s)?,
        );
        let (client_compress, server_compress) = (
            <Compress as Negociate<Client>>::negociate(&i_c, &i_s)?,
            <Compress as Negociate<Server>>::negociate(&i_c, &i_s)?,
        );
        let (client_cipher, server_cipher) = (
            <Cipher as Negociate<Client>>::negociate(&i_c, &i_s)?,
            <Cipher as Negociate<Server>>::negociate(&i_c, &i_s)?,
        );

        let (client_keys, server_keys) = match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                curve25519::as_client::<sha2::Sha256>(
                    stream,
                    v_c,
                    v_s,
                    i_c,
                    i_s,
                    &client_cipher,
                    &server_cipher,
                    &client_hmac,
                    &server_hmac,
                )
                .await?
            }
        };

        Ok(TransportPair {
            rx: Transport {
                chain: server_keys,
                state: None,
                cipher: server_cipher,
                hmac: server_hmac,
                compress: server_compress,
            },
            tx: Transport {
                chain: client_keys,
                state: None,
                cipher: client_cipher,
                hmac: client_hmac,
                compress: client_compress,
            },
        })
    }

    pub(crate) async fn as_server(
        &self,
        stream: &mut Stream<impl Pipe>,
        v_c: &Id,
        v_s: &Id,
        i_c: KexInit<'_>,
        i_s: KexInit<'_>,
        key: &PrivateKey,
    ) -> Result<TransportPair> {
        let (client_hmac, server_hmac) = (
            <Hmac as Negociate<Client>>::negociate(&i_c, &i_s)?,
            <Hmac as Negociate<Server>>::negociate(&i_c, &i_s)?,
        );
        let (client_compress, server_compress) = (
            <Compress as Negociate<Client>>::negociate(&i_c, &i_s)?,
            <Compress as Negociate<Server>>::negociate(&i_c, &i_s)?,
        );
        let (client_cipher, server_cipher) = (
            <Cipher as Negociate<Client>>::negociate(&i_c, &i_s)?,
            <Cipher as Negociate<Server>>::negociate(&i_c, &i_s)?,
        );

        let (client_keys, server_keys) = match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                curve25519::as_server::<sha2::Sha256>(
                    stream,
                    v_c,
                    v_s,
                    i_c,
                    i_s,
                    &client_cipher,
                    &server_cipher,
                    &client_hmac,
                    &server_hmac,
                    key,
                )
                .await?
            }
        };

        Ok(TransportPair {
            rx: Transport {
                chain: client_keys,
                state: None,
                cipher: client_cipher,
                hmac: client_hmac,
                compress: client_compress,
            },
            tx: Transport {
                chain: server_keys,
                state: None,
                cipher: server_cipher,
                hmac: server_hmac,
                compress: server_compress,
            },
        })
    }
}
