//! Session extension traits and helpers.

use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::{trans::DisconnectReason, Packet};

use crate::{session::Side, stream::Stream, Result};

#[cfg(doc)]
use crate::session::{client::Client, server::Server, Session};

/// The action that emerges from the [`Layer`]'s message processing.
#[derive(Debug)]
pub enum Action {
    /// Fetch a new _packet_ and call the layer stack again.
    Fetch,

    /// Forward the current _packet_ to the next layer.
    Forward(Packet),

    /// Disconnect from the peer.
    Disconnect {
        /// The reason for disconnection.
        reason: DisconnectReason,

        /// A textual description of the reason for disconnection.
        description: String,
    },
}

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
///
/// # let mut stream = futures::io::Cursor::new(Vec::<u8>::new());
/// Session::new(&mut stream, Server::default())
///     .await?
///     .add_layer(());
/// # Ok(()) }
/// ```
pub trait Layer<S: Side>: Send {
    /// A method called _after successful key-exchange_.
    fn after_kex(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> impl Future<Output = Result<()>> + Send {
        let _ = stream;

        async { Ok(()) }
    }

    /// A method called _when a packet is received_.
    fn on_recv(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
        packet: Packet,
    ) -> impl Future<Output = Result<Action>> + Send {
        let _ = stream;

        async { Ok(Action::Forward(packet)) }
    }
}

impl<S: Side> Layer<S> for () {}

impl<S: Side, A: Layer<S>, B: Layer<S>> Layer<S> for (A, B) {
    async fn after_kex(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        self.0.after_kex(stream).await?;
        self.1.after_kex(stream).await?;

        Ok(())
    }

    async fn on_recv(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
        packet: Packet,
    ) -> Result<Action> {
        let action = self.0.on_recv(stream, packet).await?;

        if let Action::Forward(packet) = action {
            self.1.on_recv(stream, packet).await
        } else {
            Ok(action)
        }
    }
}
