use ssh_packet::Packet;
use strum::{EnumString, EnumVariantNames};

#[derive(Debug, Default)]
pub struct HmacPair {
    pub rx: HmacAlg,
    pub tx: HmacAlg,

    pub seq: u32,
}

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
            Self::None => 0,

            _ => unimplemented!(),
        }
    }

    pub fn verify(&self, packet: &Packet) -> bool {
        match self {
            Self::None => true,

            _ => unimplemented!(),
        }
    }

    pub fn sign(&self, buf: &[u8]) -> Vec<u8> {
        match self {
            Self::None => vec![],

            _ => unimplemented!(),
        }
    }
}
