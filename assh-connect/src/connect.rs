use std::convert::Infallible;

use assh::{
    session::{Session, Side},
    Result,
};
use futures::{AsyncBufRead, AsyncWrite};

/// A wrapper around [`assh::session::Session`] to handle the connect layer.
pub struct Connect<I, S> {
    session: Session<I, S>,
}

impl<I: AsyncBufRead + AsyncWrite + Unpin + Send, S: Side> Connect<I, S> {
    /// Create a wrapper around the `session` to handle the connect layer.
    pub fn new(session: Session<I, S>) -> Self {
        Self { session }
    }

    /// Start processing incoming messages endlessly.
    pub async fn run(mut self) -> Result<Infallible> {
        loop {
            let packet = self.session.recv().await?;
        }
    }
}
