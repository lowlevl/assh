use ssh_key::PrivateKey;
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Pipe, Result,
    stream::{Stream, Transport},
};

// TODO: (reliability) Investigate the randomly-occuring `invalid signature` occuring against OpenSSH.
// TODO: (security) Ensure we're not susceptible to Terrapin (cf. https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/)
// and ensure we drop out debug/ignore messages in kex.

mod meta;
pub use meta::KexMeta;

mod curve25519;

impl super::Negociate for Kex {
    const ERR: Error = Error::NoCommonKex;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.kex_algorithms
    }
}

// TODO: (feature) Implement the following legacy key-exchange methods (`diffie-hellman-group14-sha256`, `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1`).
// TODO: (feature) Implement the post-quantum key-exchange methods (`sntrup761x25519-sha512`, `mlkem768x25519-sha256`, and more ?).

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
        client: KexMeta<'_>,
        server: KexMeta<'_>,
    ) -> Result<Transport> {
        match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                curve25519::as_client::<sha2::Sha256>(stream, client, server).await
            }
        }
    }

    pub(crate) async fn as_server(
        &self,
        stream: &mut Stream<impl Pipe>,
        client: KexMeta<'_>,
        server: KexMeta<'_>,
        key: &PrivateKey,
    ) -> Result<Transport> {
        match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                curve25519::as_server::<sha2::Sha256>(stream, client, server, key).await
            }
        }
    }
}
