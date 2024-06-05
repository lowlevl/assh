use thiserror::Error;

/// The error types that can occur when manipulating this crate.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// Transport error.
    #[error(transparent)]
    Transport(#[from] assh::Error),

    /// The channel has been closed.
    #[error("The channel has been closed")]
    ChannelClosed,
}

/// A handy [`std::result::Result`] type alias bounding the [`enum@Error`] struct as `E`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
