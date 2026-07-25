use digest::{Digest, FixedOutputReset};
use hmac::{
    KeyInit, Mac,
    digest::{DynDigest, MacError},
};
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Result,
    side::{client::Client, server::Server},
};

impl super::Negociate<Client> for Hmac {
    const ERR: Error = Error::NoCommonHmac;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.mac_algorithms_client_to_server
    }
}

impl super::Negociate<Server> for Hmac {
    const ERR: Error = Error::NoCommonHmac;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.mac_algorithms_server_to_client
    }
}

/// SSH hmac algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, EnumString, AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub enum Hmac {
    /// HMAC with sha-2-512 digest on encrypted message.
    #[strum(serialize = "hmac-sha2-512-etm@openssh.com")]
    HmacSha512ETM,

    /// HMAC with sha-2-256 digest on encrypted message.
    #[strum(serialize = "hmac-sha2-256-etm@openssh.com")]
    HmacSha256ETM,

    /// HMAC with sha-2-512 digest.
    #[strum(serialize = "hmac-sha2-512")]
    HmacSha512,

    /// HMAC with sha-2-256 digest.
    #[strum(serialize = "hmac-sha2-256")]
    HmacSha256,

    /// HMAC with sha-1 digest on encrypted message.
    #[strum(serialize = "hmac-sha1-etm@openssh.com")]
    HmacSha1ETM,

    /// HMAC with sha-1 digest.
    HmacSha1,

    /// HMAC with md5 digest on encrypted message.
    #[strum(serialize = "hmac-md5-etm@openssh.com")]
    HmacMd5ETM,

    /// HMAC with md5 digest.
    HmacMd5,

    /// No HMAC algorithm.
    None,
}

pub type HmacBuf = heapless::Vec<u8, 64>;

#[derive(Debug, Default)]
pub struct State {
    etm: bool,
    core: Core,
}

#[derive(Debug, Default)]
enum Core {
    HmacSha512(hmac::HmacReset<sha2::Sha512>),
    HmacSha256(hmac::HmacReset<sha2::Sha256>),
    HmacSha1(hmac::HmacReset<sha1::Sha1>),
    HmacMd5(hmac::HmacReset<md5::Md5>),
    #[default]
    None,
}

impl State {
    pub fn new<const K: u8, H: Digest + FixedOutputReset>(
        hmac: &Hmac,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        const SHA512_KS: usize = 64;
        const SHA256_KS: usize = 32;
        const SHA1_KS: usize = 20;
        const MD5_KS: usize = 16;

        fn new<const S: usize, H: Digest + FixedOutputReset, M: KeyInit>(
            kind: u8,
            secret: &[u8],
            hash: &[u8],
            session_id: &[u8],
        ) -> M {
            let key = super::kdf::<S, H>(kind, secret, hash, session_id);

            M::new_from_slice(&key).expect("hmac accepts any key size")
        }

        Self {
            etm: matches!(
                hmac,
                Hmac::HmacSha512ETM | Hmac::HmacSha256ETM | Hmac::HmacSha1ETM | Hmac::HmacMd5ETM
            ),

            core: match hmac {
                Hmac::HmacSha512ETM | Hmac::HmacSha512 => {
                    Core::HmacSha512(new::<SHA512_KS, H, _>(K, secret, hash, session_id))
                }
                Hmac::HmacSha256ETM | Hmac::HmacSha256 => {
                    Core::HmacSha256(new::<SHA256_KS, H, _>(K, secret, hash, session_id))
                }
                Hmac::HmacSha1ETM | Hmac::HmacSha1 => {
                    Core::HmacSha1(new::<SHA1_KS, H, _>(K, secret, hash, session_id))
                }
                Hmac::HmacMd5ETM | Hmac::HmacMd5 => {
                    Core::HmacMd5(new::<MD5_KS, H, _>(K, secret, hash, session_id))
                }
                Hmac::None => Core::None,
            },
        }
    }

    pub fn compute(&mut self, seq: u32, buf: &[u8]) -> HmacBuf {
        fn compute<D: Mac + FixedOutputReset>(state: &mut D, seq: u32, buf: &[u8]) -> HmacBuf {
            Mac::update(state, &seq.to_be_bytes());
            Mac::update(state, buf);

            HmacBuf::from_slice(&state.finalize_reset().into_bytes())
                .expect("HMAC output is bigger than the alloted storage")
        }

        match &mut self.core {
            Core::HmacSha512(state) => compute(state, seq, buf),
            Core::HmacSha256(state) => compute(state, seq, buf),
            Core::HmacSha1(state) => compute(state, seq, buf),
            Core::HmacMd5(state) => compute(state, seq, buf),
            Core::None => Default::default(),
        }
    }

    pub fn verify(&mut self, seq: u32, buf: &[u8], mac: &[u8]) -> Result<(), MacError> {
        fn verify<D: Mac + FixedOutputReset>(
            state: &mut D,
            seq: u32,
            buf: &[u8],
            mac: &[u8],
        ) -> Result<(), MacError> {
            Mac::update(state, &seq.to_be_bytes());
            Mac::update(state, buf);

            state.verify_slice_reset(mac)
        }

        match &mut self.core {
            Core::HmacSha512(state) => verify(state, seq, buf, mac),
            Core::HmacSha256(state) => verify(state, seq, buf, mac),
            Core::HmacSha1(state) => verify(state, seq, buf, mac),
            Core::HmacMd5(state) => verify(state, seq, buf, mac),
            Core::None => Ok(()),
        }
    }

    pub fn size(&self) -> usize {
        match &self.core {
            Core::HmacSha512(state) => state.output_size(),
            Core::HmacSha256(state) => state.output_size(),
            Core::HmacSha1(state) => state.output_size(),
            Core::HmacMd5(state) => state.output_size(),
            Core::None => 0,
        }
    }

    pub fn etm(&self) -> bool {
        self.etm
    }
}
