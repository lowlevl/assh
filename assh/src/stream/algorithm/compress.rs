use std::io::{Read, Write};

use ssh_packet::trans::KexInit;
use strum::{AsRefStr, EnumString};

use crate::{Error, Result};

pub fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<(Compress, Compress)> {
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

// TODO: Fix compression algorithms, not working right now.

/// SSH compression algorithms.
#[non_exhaustive]
#[derive(Debug, Default, PartialEq, EnumString, AsRefStr)]
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
