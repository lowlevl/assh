use thiserror::Error;

/// The error types that can occur when manipulating this crate.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// Identifier parsing error.
    #[error(transparent)]
    Id(#[from] ssh_packet::Error),

    /// Binary (de)-serialization error.
    #[error(transparent)]
    Binary(#[from] ssh_packet::binrw::Error),

    /// I/O Error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// SSH Key error.
    #[error(transparent)]
    Key(#[from] ssh_key::Error),

    /// Packet integrity error.
    #[error(transparent)]
    Integrity(#[from] digest::MacError),

    /// Signature error during the key-exchange.
    #[error(transparent)]
    Signature(#[from] signature::Error),

    /// Error while encrypting or decrypting messages.
    #[error("The cipher ended up in an error")]
    Cipher,

    /// No common kex algorithm found between both sides.
    #[error("Unable to negociate a common kex algorithm")]
    NoCommonKex,

    /// No common key algorithm found between both sides.
    #[error("Unable to negociate a common host key algorithm")]
    NoCommonKey,

    /// No common cipher algorithm found between both sides.
    #[error("Unable to negociate a common encryption algorithm")]
    NoCommonCipher,

    /// No common hmac algorithm found between both sides.
    #[error("Unable to negociate a common HMAC algorithm")]
    NoCommonHmac,

    /// No common compression algorithm found between both sides.
    #[error("Unable to negociate a common compression algorithm")]
    NoCommonCompression,

    /// Provided algorithm wasn't supported.
    #[error("Algorithm is unsupported")]
    UnsupportedAlgorithm,

    /// Protocol error in the key-exchange.
    #[error("Error in the kex-exchange algorithm")]
    KexError,

    /// The session has been disconnected.
    #[error("The session has been disconnected")]
    Disconnected,
}

/// A handy [`std::result::Result`] type alias bounding the [`enum@Error`] struct as `E`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
