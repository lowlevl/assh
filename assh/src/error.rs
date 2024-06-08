//! Collection of error handling types and aliases.

use ssh_packet::trans;
use thiserror::Error;

/// The disconnection side for [`DisconnectedError`].
#[derive(Debug, Clone)]
pub enum DisconnectedBy {
    /// The session has been disconnected by _us_.
    Us,

    /// The session has been disconnected by _them_.
    Them,
}

/// The error type describing disconnect.
#[must_use]
#[derive(Debug, Error, Clone)]
#[error("The session has been disconnected by {by:?} for {reason:?}: {description}")]
pub struct DisconnectedError {
    /// Side that sent the disconnect message.
    pub by: DisconnectedBy,

    /// Reason for disconnect.
    pub reason: trans::DisconnectReason,

    /// Description of the disconnect reason.
    pub description: String,
}

/// The error types that can occur when manipulating this crate.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// Identifier parsing error.
    #[error(transparent)]
    Id(#[from] ssh_packet::Error),

    /// I/O Error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Binary (de)-serialization error.
    #[error(transparent)]
    Binary(#[from] ssh_packet::binrw::Error),

    /// SSH Key error.
    #[error(transparent)]
    Key(#[from] ssh_key::Error),

    /// Packet integrity error.
    #[error(transparent)]
    Integrity(#[from] digest::MacError),

    /// Signature error during the key-exchange.
    #[error(transparent)]
    Signature(#[from] signature::Error),

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

    /// Protocol error in the key-exchange.
    #[error("Error in the kex-exchange algorithm")]
    KexError,

    /// Error while encrypting or decrypting messages.
    #[error("The cipher ended up in an error")]
    Cipher,

    /// The message received was unexpected in the current context.
    #[error("Peer sent a message that made no sense in the current context")]
    UnexpectedMessage,

    /// The session has been disconnected.
    #[error(transparent)]
    Disconnected(#[from] DisconnectedError),
}

/// A handy [`std::result::Result`] type alias bounding the [`enum@Error`] struct as `E`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
