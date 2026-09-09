use bytes::{Bytes, BytesMut};
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Result,
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
    pub(crate) fn compress(&mut self, buf: &[u8], output: &mut BytesMut) -> Result<()> {
        output.extend_from_slice(buf);

        Ok(())
    }

    pub(crate) fn decompress(&mut self, buf: BytesMut, _maxlen: usize) -> Result<Bytes> {
        Ok(buf.freeze())
    }
}
