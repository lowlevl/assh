//! Session extension traits and helpers.

use async_trait::async_trait;
use futures::{AsyncBufRead, AsyncWrite};

use crate::{session::Side, stream::Stream, Result};

#[cfg(doc)]
use crate::session::{client::Client, server::Server, Session};

/// An extension layer for a [`Session`].
///
/// A [`Layer`] can work either for both of the sides ([`Client`] and [`Server`])
/// or be constrained to a single [`Side`] using the type parameter.
///
/// In example, the no-op layer (`()`) can be used on both sides as seen there:
/// ```rust,no_run
/// # async fn test() -> Result<(), Box<dyn std::error::Error>> {
/// # use assh::session::{Session, client::Client, server::Server};
/// # let mut stream = futures::io::Cursor::new(Vec::<u8>::new());
/// Session::new(&mut stream, Client::default())
///     .await?
///     .add_layer(());
/// # let mut stream = futures::io::Cursor::new(Vec::<u8>::new());
/// Session::new(&mut stream, Server::default())
///     .await?
///     .add_layer(());
/// # Ok(()) }
/// ```
#[async_trait]
pub trait Layer<S: Side>: Send {
    /// A method called _after successful key-exchange_.
    async fn on_kex(
        &mut self,
        _stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        Ok(())
    }

    /// A method called _before a message is received_.
    async fn on_recv(
        &mut self,
        _stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl<S: Side> Layer<S> for () {}

#[async_trait]
impl<S: Side, A: Layer<S>, B: Layer<S>> Layer<S> for (A, B) {
    async fn on_kex(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        self.0.on_kex(stream).await?;
        self.1.on_kex(stream).await?;

        Ok(())
    }

    async fn on_recv(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        self.0.on_recv(stream).await?;
        self.1.on_recv(stream).await?;

        Ok(())
    }
}
