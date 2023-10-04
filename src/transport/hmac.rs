use digest::OutputSizeUser;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use ssh_packet::Packet;
use strum::{EnumString, EnumVariantNames};

#[derive(Debug, Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum HmacAlg {
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

impl HmacAlg {
    pub fn size(&self) -> usize {
        match self {
            Self::HmacSha512ETM => Sha512::output_size(),
            Self::HmacSha256ETM => Sha256::output_size(),
            Self::HmacSha512 => Sha512::output_size(),
            Self::HmacSha256 => Sha256::output_size(),
            Self::HmacSha1ETM => Sha1::output_size(),
            Self::HmacSha1 => Sha1::output_size(),
            Self::None => 0,
        }
    }

    pub fn etm(&self) -> bool {
        matches!(
            self,
            Self::HmacSha512ETM | Self::HmacSha256ETM | Self::HmacSha1ETM
        )
    }

    pub fn verify(&self, seq: u32, buf: &[u8], key: &[u8]) -> bool {
        match self {
            Self::None => true,

            _ => unimplemented!(),
        }
    }

    pub fn sign(&self, seq: u32, buf: &[u8], key: &[u8]) -> Vec<u8> {
        match self {
            Self::HmacSha512ETM | Self::HmacSha512 => Hmac::<Sha512>::new_from_slice(key)
                .expect("Key derivation failed horribly")
                .chain_update(seq.to_be_bytes())
                .chain_update(buf)
                .finalize()
                .into_bytes()
                .to_vec(),
            Self::HmacSha256ETM | Self::HmacSha256 => Hmac::<Sha256>::new_from_slice(key)
                .expect("Key derivation failed horribly")
                .chain_update(seq.to_be_bytes())
                .chain_update(buf)
                .finalize()
                .into_bytes()
                .to_vec(),
            Self::HmacSha1ETM | Self::HmacSha1 => Hmac::<Sha1>::new_from_slice(key)
                .expect("Key derivation failed horribly")
                .chain_update(seq.to_be_bytes())
                .chain_update(buf)
                .finalize()
                .into_bytes()
                .to_vec(),
            Self::None => Default::default(),
        }
    }
}
