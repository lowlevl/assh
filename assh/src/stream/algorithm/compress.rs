use bytes::{Bytes, BytesMut};
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error,
    side::{client::Client, server::Server},
};

impl super::Negociate<Client> for Compress {
    const ERR: Error = Error::NoCommonCompression;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.compression_algorithms_client_to_server
    }
}

impl super::Negociate<Server> for Compress {
    const ERR: Error = Error::NoCommonCompression;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.compression_algorithms_server_to_client
    }
}

// TODO: (compliance) Fix compression algorithms, not working right now.

/// SSH compression algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, EnumString, AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub enum Compress {
    /// zlib compression (OpenSSH mode).
    #[strum(serialize = "zlib@openssh.com")]
    ZlibOpenssh,

    /// zlib compression.
    Zlib,

    /// No compression algorithm.
    None,
}

#[derive(Debug, Default)]
pub struct State<T> {
    delayed: bool,
    core: T,
}

#[derive(Debug, Default)]
pub enum Compression {
    Zlib(flate2::Compress),
    #[default]
    None,
}

#[derive(Debug, Default)]
pub enum Decompression {
    Zlib(flate2::Decompress),
    #[default]
    None,
}

impl State<Compression> {
    pub fn new(compress: &Compress) -> Self {
        let delayed = matches!(compress, Compress::ZlibOpenssh);

        Self {
            delayed,
            core: match compress {
                Compress::ZlibOpenssh | Compress::Zlib => {
                    Compression::Zlib(flate2::Compress::new(flate2::Compression::fast(), true))
                }

                Compress::None => Compression::None,
            },
        }
    }

    pub fn compress(
        &mut self,
        input: &[u8],
        output: &mut BytesMut,
    ) -> Result<(), flate2::CompressError> {
        output.resize(input.len(), 0); // reserve `input`'s size
        output[..].copy_from_slice(input);

        Ok(())
    }
}

impl State<Decompression> {
    pub fn new(compress: &Compress) -> Self {
        let delayed = matches!(compress, Compress::ZlibOpenssh);

        Self {
            delayed,
            core: match compress {
                Compress::ZlibOpenssh | Compress::Zlib => {
                    Decompression::Zlib(flate2::Decompress::new(true))
                }

                Compress::None => Decompression::None,
            },
        }
    }

    pub fn decompress(&mut self, buf: BytesMut) -> Result<Bytes, flate2::DecompressError> {
        Ok(buf.freeze())
    }
}
