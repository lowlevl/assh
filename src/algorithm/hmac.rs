use digest::OutputSizeUser;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use ssh_packet::trans::KexInit;
use strum::{EnumString, EnumVariantNames};

use crate::{Error, Result};

#[derive(Debug, Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum Hmac {
    #[strum(serialize = "hmac-sha2-512-etm@openssh.com")]
    HmacSha512ETM,

    #[strum(serialize = "hmac-sha2-256-etm@openssh.com")]
    HmacSha256ETM,

    #[strum(serialize = "hmac-sha2-512")]
    HmacSha512,

    #[strum(serialize = "hmac-sha2-256")]
    HmacSha256,

    #[strum(serialize = "hmac-sha1-etm@openssh.com")]
    HmacSha1ETM,

    HmacSha1,

    /// No HMAC algorithm.
    #[default]
    None,
}

impl Hmac {
    pub fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<(Self, Self)> {
        Ok((
            clientkex
                .mac_algorithms_client_to_server
                .preferred_in(&serverkex.mac_algorithms_client_to_server)
                .ok_or(Error::NoCommonCipher)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            clientkex
                .mac_algorithms_server_to_client
                .preferred_in(&serverkex.mac_algorithms_server_to_client)
                .ok_or(Error::NoCommonHmac)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
        ))
    }

    pub fn verify(
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
            Self::None => Ok(()),
        }
    }

    pub fn sign(&self, seq: u32, buf: &[u8], key: &[u8]) -> Vec<u8> {
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
            Self::None => Default::default(),
        }
    }
}

impl ssh_packet::Mac for Hmac {
    fn size(&self) -> usize {
        match self {
            Self::HmacSha512ETM | Self::HmacSha512 => Sha512::output_size(),
            Self::HmacSha256ETM | Self::HmacSha256 => Sha256::output_size(),
            Self::HmacSha1ETM | Self::HmacSha1 => Sha1::output_size(),
            Self::None => 0,
        }
    }

    fn etm(&self) -> bool {
        matches!(
            self,
            Self::HmacSha512ETM | Self::HmacSha256ETM | Self::HmacSha1ETM
        )
    }
}
