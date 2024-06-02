use ssh_packet::connect;
use thiserror::Error;

/// The error types that can occur when manipulating this crate.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// Transport error.
    #[error(transparent)]
    Transport(#[from] assh::Error),

    /// The peer refused to open the channel.
    #[error("Peer refused the opening of the channel: {message} ({reason:?})")]
    ChannelOpenFailure {
        /// The reason for failure.
        reason: connect::ChannelOpenFailureReason,

        /// A textual message to acompany the reason.
        message: String,
    },

    /// The channel has been closed.
    #[error("The channel has been closed")]
    ChannelClosed,
}

/// A handy [`std::result::Result`] type alias bounding the [`enum@Error`] struct as `E`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
