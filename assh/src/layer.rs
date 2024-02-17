//! Session extension traits and helpers.

use async_trait::async_trait;
use ssh_packet::Message;

use crate::{stream::Stream, Result};

#[cfg(doc)]
use crate::session::Session;

/// A [`Session`] extension, either client-side or server-side.
#[async_trait(?Send)]
pub trait Layer {
    /// A method called on successful kex-exchange.
    async fn on_kex<I>(&mut self, stream: &mut Stream<I>) -> Result<()>;

    /// A method called, _after a successful key-exchange_, after a message is received.
    async fn on_recv<I>(&mut self, stream: &mut Stream<I>, message: Message) -> Result<Message>;

    /// A method called, _after a successful key-exchange_, before a message is sent.
    async fn on_send<I>(&mut self, stream: &mut Stream<I>) -> Result<()>;
}

#[async_trait(?Send)]
impl Layer for () {
    async fn on_kex<I>(&mut self, _stream: &mut Stream<I>) -> Result<()> {
        Ok(())
    }

    async fn on_recv<I>(&mut self, _stream: &mut Stream<I>, message: Message) -> Result<Message> {
        Ok(message)
    }

    async fn on_send<I>(&mut self, _stream: &mut Stream<I>) -> Result<()> {
        Ok(())
    }
}

/// An helper to join multiple [`Layer`]s into one.
#[derive(Debug)]
pub struct Layers<L: Layer, N: Layer>(pub L, pub N);

#[async_trait(?Send)]
impl<L: Layer, N: Layer> Layer for Layers<L, N> {
    async fn on_kex<I>(&mut self, stream: &mut Stream<I>) -> Result<()> {
        self.0.on_kex(stream).await?;
        self.1.on_kex(stream).await?;

        Ok(())
    }

    async fn on_recv<I>(&mut self, stream: &mut Stream<I>, message: Message) -> Result<Message> {
        let message = self.0.on_recv(stream, message).await?;
        let message = self.1.on_recv(stream, message).await?;

        Ok(message)
    }

    async fn on_send<I>(&mut self, stream: &mut Stream<I>) -> Result<()> {
        self.0.on_send(stream).await?;
        self.1.on_send(stream).await?;

        Ok(())
    }
}
