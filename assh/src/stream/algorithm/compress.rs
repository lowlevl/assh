use bytes::{Bytes, BytesMut};
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};
use zlib_rs::{Deflate, DeflateError, DeflateFlush, Inflate, InflateError, InflateFlush, Status};

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

const DEFAULT_WINDOW_BITS: u8 = 15;

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

#[derive(Default)]
pub enum Compression {
    Zlib(Deflate),
    #[default]
    None,
}

impl std::fmt::Debug for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zlib(_) => write!(f, "Zlib"),
            Self::None => write!(f, "None"),
        }
    }
}

#[derive(Default)]
pub enum Decompression {
    Zlib(Inflate),
    #[default]
    None,
}

impl std::fmt::Debug for Decompression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zlib(_) => write!(f, "Zlib"),
            Self::None => write!(f, "None"),
        }
    }
}

impl State<Compression> {
    pub fn new(compress: &Compress) -> Self {
        let delayed = matches!(compress, Compress::ZlibOpenssh);

        Self {
            delayed,
            core: match compress {
                Compress::ZlibOpenssh | Compress::Zlib => {
                    Compression::Zlib(Deflate::new(1, true, DEFAULT_WINDOW_BITS))
                }

                Compress::None => Compression::None,
            },
        }
    }

    pub fn compress(&mut self, buf: &[u8], output: &mut BytesMut) -> Result<(), DeflateError> {
        match &mut self.core {
            Compression::Zlib(state) => {
                output.resize(zlib_rs::compress_bound(buf.len()), 0);

                let ins = state.total_in();
                let outs = state.total_out();

                loop {
                    let status = state.compress(
                        &buf[(state.total_in() - ins) as usize..],
                        &mut output[(state.total_out() - outs) as usize..],
                        DeflateFlush::PartialFlush,
                    )?;

                    tracing::info!(
                        "comp :: in: {}, out: {}, {status:?}",
                        state.total_in() - ins,
                        state.total_out() - outs
                    );

                    if let Status::Ok = status {
                        break;
                    }
                }

                output.truncate((state.total_out() - outs) as usize);

                Ok(())
            }

            Compression::None => {
                output.extend_from_slice(buf);

                Ok(())
            }
        }
    }
}

impl State<Decompression> {
    pub fn new(compress: &Compress) -> Self {
        let delayed = matches!(compress, Compress::ZlibOpenssh);

        Self {
            delayed,
            core: match compress {
                Compress::ZlibOpenssh | Compress::Zlib => {
                    Decompression::Zlib(Inflate::new(true, DEFAULT_WINDOW_BITS))
                }

                Compress::None => Decompression::None,
            },
        }
    }

    pub fn decompress(&mut self, buf: BytesMut, maxlen: usize) -> Result<Bytes, InflateError> {
        const GROWTH_FACTOR: usize = 2;

        match &mut self.core {
            Decompression::Zlib(state) => {
                let mut output = BytesMut::zeroed(buf.len());

                let ins = state.total_in();
                let outs = state.total_out();

                loop {
                    let status = state.decompress(
                        &buf[(state.total_in() - ins) as usize..],
                        &mut output[(state.total_out() - outs) as usize..],
                        InflateFlush::NoFlush,
                    )?;

                    tracing::info!(
                        "decomp :: in: {}/{}, out: {}/{}, {status:?}",
                        state.total_in() - ins,
                        buf.len(),
                        state.total_out() - outs,
                        output.len()
                    );

                    match status {
                        Status::Ok
                            if (state.total_in() - ins) != buf.len() as u64
                                || (state.total_out() - outs) == output.len() as u64 =>
                        {
                            output.resize(output.len() * GROWTH_FACTOR, 0);
                            tracing::info!("resized: {}", output.len());
                        }

                        _ => break,
                    }
                }

                output.truncate((state.total_out() - outs) as usize);

                tracing::info!("final decomp: {}", output.len());

                Ok(output.freeze())
            }

            Decompression::None => Ok(buf.freeze()),
        }
    }
}
