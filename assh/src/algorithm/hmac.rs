use digest::OutputSizeUser;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Result,
    side::{client::Client, server::Server},
};

use super::Negociate;

impl Negociate<Client> for Hmac {
    const ERR: Error = Error::NoCommonHmac;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.mac_algorithms_client_to_server
    }
}

impl Negociate<Server> for Hmac {
    const ERR: Error = Error::NoCommonHmac;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.mac_algorithms_server_to_client
    }
}

/// SSH hmac algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, EnumString, AsRefStr)]
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
    #[default]
    None,
}

impl Hmac {
    pub(crate) fn verify(
        &self,
        seq: u32,
        buf: &[u8],
        key: &[u8],
        mac: &[u8],
    ) -> Result<(), digest::MacError> {
        fn verify<D: digest::Mac + digest::KeyInit>(
            seq: u32,
            buf: &[u8],
            key: &[u8],
            mac: &[u8],
        ) -> Result<(), digest::MacError> {
            <D as digest::Mac>::new_from_slice(key)
                .expect("Key derivation failed horribly")
                .chain_update(seq.to_be_bytes())
                .chain_update(buf)
                .verify(mac.into())
        }

        match self {
            Self::HmacSha512ETM | Self::HmacSha512 => {
                verify::<hmac::Hmac<Sha512>>(seq, buf, key, mac)
            }
            Self::HmacSha256ETM | Self::HmacSha256 => {
                verify::<hmac::Hmac<Sha256>>(seq, buf, key, mac)
            }
            Self::HmacSha1ETM | Self::HmacSha1 => verify::<hmac::Hmac<Sha1>>(seq, buf, key, mac),
            Self::HmacMd5ETM | Self::HmacMd5 => verify::<hmac::Hmac<Md5>>(seq, buf, key, mac),
            Self::None => Ok(()),
        }
    }

    pub(crate) fn sign(&self, seq: u32, buf: &[u8], key: &[u8]) -> Vec<u8> {
        fn sign<D: digest::Mac + digest::KeyInit>(seq: u32, buf: &[u8], key: &[u8]) -> Vec<u8> {
            <D as digest::Mac>::new_from_slice(key)
                .expect("Key derivation failed horribly")
                .chain_update(seq.to_be_bytes())
                .chain_update(buf)
                .finalize()
                .into_bytes()
                .to_vec()
        }

        match self {
            Self::HmacSha512ETM | Self::HmacSha512 => sign::<hmac::Hmac<Sha512>>(seq, buf, key),
            Self::HmacSha256ETM | Self::HmacSha256 => sign::<hmac::Hmac<Sha256>>(seq, buf, key),
            Self::HmacSha1ETM | Self::HmacSha1 => sign::<hmac::Hmac<Sha1>>(seq, buf, key),
            Self::HmacMd5ETM | Self::HmacMd5 => sign::<hmac::Hmac<Md5>>(seq, buf, key),
            Self::None => Default::default(),
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Self::HmacSha512ETM | Self::HmacSha512 => Sha512::output_size(),
            Self::HmacSha256ETM | Self::HmacSha256 => Sha256::output_size(),
            Self::HmacSha1ETM | Self::HmacSha1 => Sha1::output_size(),
            Self::HmacMd5ETM | Self::HmacMd5 => Md5::output_size(),
            Self::None => 0,
        }
    }

    pub(crate) fn etm(&self) -> bool {
        matches!(
            self,
            Self::HmacSha512ETM | Self::HmacSha256ETM | Self::HmacSha1ETM | Self::HmacMd5ETM
        )
    }
}
