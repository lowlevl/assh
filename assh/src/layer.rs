//! Session extension traits and helpers.

use async_trait::async_trait;

use crate::{session::Side, stream::Stream, Result};

#[cfg(doc)]
use crate::session::{client::Client, server::Server, Session};

/// A [`Session`] extension layer.
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
#[async_trait(?Send)]
pub trait Layer<S: Side> {
    /// A method called on successful kex-exchange.
    async fn on_kex<I>(&mut self, _stream: &mut Stream<I>) -> Result<()> {
        Ok(())
    }

    /// A method called, _after a successful key-exchange_, after a message is received.
    async fn on_recv<I>(&mut self, _stream: &mut Stream<I>) -> Result<()> {
        Ok(())
    }
}

#[async_trait(?Send)]
impl<S: Side> Layer<S> for () {}

/// An helper to join multiple [`Layer`]s into one.
#[derive(Debug)]
pub struct Layers<L, N>(pub L, pub N);

#[async_trait(?Send)]
impl<S: Side, L: Layer<S>, N: Layer<S>> Layer<S> for Layers<L, N> {
    async fn on_kex<I>(&mut self, stream: &mut Stream<I>) -> Result<()> {
        self.0.on_kex(stream).await?;
        self.1.on_kex(stream).await?;

        Ok(())
    }

    async fn on_recv<I>(&mut self, stream: &mut Stream<I>) -> Result<()> {
        self.0.on_recv(stream).await?;
        self.1.on_recv(stream).await?;

        Ok(())
    }
}
