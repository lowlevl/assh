use std::io::{Read, Write};

use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Result,
    side::{client::Client, server::Server},
};

use super::Negociate;

impl Negociate<Client> for Compress {
    const ERR: Error = Error::NoCommonCompression;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.compression_algorithms_client_to_server
    }
}

impl Negociate<Server> for Compress {
    const ERR: Error = Error::NoCommonCompression;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.compression_algorithms_server_to_client
    }
}

// TODO: (compliance) Fix compression algorithms, not working right now.

/// SSH compression algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, EnumString, AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub enum Compress {
    /// zlib compression (OpenSSH mode).
    #[strum(serialize = "zlib@openssh.com")]
    ZlibOpenssh,

    /// zlib compression.
    Zlib,

    /// No compression algorithm.
    #[default]
    None,
}

impl Compress {
    pub(crate) fn decompress(&self, buf: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Self::ZlibOpenssh | Self::Zlib => {
                let mut buffer = Vec::with_capacity(buf.len());
                let decoder = libflate::zlib::Decoder::new(std::io::Cursor::new(buf))?;

                decoder
                    .take(ssh_packet::PACKET_MAX_SIZE as u64)
                    .read_to_end(&mut buffer)?;

                Ok(buffer)
            }
            Self::None => Ok(buf),
        }
    }

    pub(crate) fn compress(&self, buf: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::ZlibOpenssh | Self::Zlib => {
                let mut encoder = libflate::zlib::Encoder::new(Vec::with_capacity(buf.len()))?;

                encoder.write_all(buf)?;

                Ok(encoder.finish().into_result()?)
            }
            Self::None => Ok(buf.into()),
        }
    }
}
