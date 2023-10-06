use thiserror::Error;

/// The error types that can occur when manipulating this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Packet(#[from] ssh_packet::Error),

    #[error(transparent)]
    Binary(#[from] ssh_packet::binrw::Error),

    #[error(transparent)]
    Crypto(#[from] ring::error::Unspecified),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] ssh_key::Error),

    #[error(transparent)]
    Integrity(#[from] digest::MacError),

    #[error("The cipher ended up in an error")]
    Cipher,

    #[error("Unable to negociate a common kex algorithm")]
    NoCommonKex,

    #[error("Unable to negociate a common key algorithm")]
    NoCommonKey,

    #[error("Unable to negociate a common encryption algorithm")]
    NoCommonCipher,

    #[error("Unable to negociate a common HMAC algorithm")]
    NoCommonHmac,

    #[error("Unable to negociate a common compression algorithm")]
    NoCommonCompression,

    #[error("Algorithm is unsupported")]
    UnsupportedAlgorithm,

    #[error("Error in the kex-exchange algorithm")]
    KexError,

    #[error("Received packet padding is mismatched, expected {0} got {1}")]
    Padding(usize, usize),

    #[error("The session has been disconnected")]
    Disconnected,
}

/// A handy [`std::result::Result`] type alias bounding the [`enum@Error`] struct as `E`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
