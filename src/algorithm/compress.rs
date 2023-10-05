use ssh_packet::trans::KexInit;
use strum::{EnumString, EnumVariantNames};

use crate::{Error, Result};

#[derive(Debug, Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum Compress {
    /// Zlib compression.
    Zlib,

    /// Zlib compression (extension name).
    #[strum(serialize = "zlib@openssh.com")]
    ZlibExt,

    /// No compression.
    #[default]
    None,
}

impl Compress {
    pub fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<(Self, Self)> {
        Ok((
            clientkex
                .compression_algorithms_client_to_server
                .preferred_in(&serverkex.compression_algorithms_client_to_server)
                .ok_or(Error::NoCommonCompression)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            clientkex
                .compression_algorithms_server_to_client
                .preferred_in(&serverkex.compression_algorithms_server_to_client)
                .ok_or(Error::NoCommonCompression)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
        ))
    }

    pub fn decompress(&self, buf: Vec<u8>) -> Vec<u8> {
        match self {
            Self::None => buf,
            Self::Zlib | Self::ZlibExt => unimplemented!(),
        }
    }

    pub fn compress(&self, buf: Vec<u8>) -> Vec<u8> {
        match self {
            Self::None => buf,
            Self::Zlib | Self::ZlibExt => unimplemented!(),
        }
    }
}
