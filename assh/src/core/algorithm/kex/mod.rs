use std::task;

use ssh_key::PrivateKey;
use ssh_packet::arch::NameList;
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Pipe, Result,
    core::{Core, rx, tx},
};

// TODO: (reliability) Investigate the randomly-occuring `invalid signature` occuring against OpenSSH.
// TODO: (security) Ensure we're not susceptible to Terrapin (cf. https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/)
// and ensure we drop out debug/ignore messages in kex.

pub use ssh_packet::trans::KexInit;

mod meta;
pub use meta::Meta;

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
    pub(crate) fn as_client(&self, client: Meta, server: Meta) -> Client {
        match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                Client::Curve25519Sha256(Clientside {
                    client,
                    server,
                    kex: Default::default(),
                })
            }
        }
    }

    pub(crate) fn as_server(&self, client: Meta, server: Meta, key: PrivateKey) -> Server {
        match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                Server::Curve25519Sha256(Serverside {
                    client,
                    server,
                    key,
                    kex: Default::default(),
                })
            }
        }
    }
}

pub trait Exchange: Send + Sync {
    /// Proceed through the key-exchange state machine,
    /// yielding a [`rx::Transport`] + [`tx::Transport`] tuple.
    fn poll(
        &mut self,
        cx: &mut task::Context<'_>,
        core: &mut Core<impl Pipe>,
    ) -> task::Poll<Result<(rx::Transport, tx::Transport)>>;
}

pub struct Clientside<K> {
    client: Meta,
    server: Meta,
    kex: K,
}

pub enum Client {
    Curve25519Sha256(Clientside<curve25519::Client>),
}

impl Exchange for Client {
    fn poll(
        &mut self,
        cx: &mut task::Context<'_>,
        core: &mut Core<impl Pipe>,
    ) -> task::Poll<Result<(rx::Transport, tx::Transport)>> {
        match self {
            Self::Curve25519Sha256(kex) => kex.poll(cx, core),
        }
    }
}

pub struct Serverside<K> {
    client: Meta,
    server: Meta,
    key: PrivateKey,
    kex: K,
}

pub enum Server {
    Curve25519Sha256(Serverside<curve25519::Server>),
}

impl Exchange for Server {
    fn poll(
        &mut self,
        cx: &mut task::Context<'_>,
        core: &mut Core<impl Pipe>,
    ) -> task::Poll<Result<(rx::Transport, tx::Transport)>> {
        match self {
            Self::Curve25519Sha256(kex) => kex.poll(cx, core),
        }
    }
}
