use std::convert::Infallible;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Packet(#[from] ssh_packet::Error<Infallible>),

    #[error(transparent)]
    PacketCipher(#[from] ssh_packet::Error<ssh_key::Error>),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("The session has been disconnected")]
    Disconnected,

    #[error("Unable to negociate a common kex algorithm")]
    NoCommonKex,

    #[error("Unable to negociate a common encryption algorithm")]
    NoCommonEncryption,

    #[error("Unable to negociate a common HMAC algorithm")]
    NoCommonHmac,

    #[error("Unable to negociate a common compression algorithm")]
    NoCommonCompression,

    #[error("Received algorithm is unsupported")]
    UnsupportedAlgorithm,

    #[error("Error in the kex-exchange algorithm")]
    KexError,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
