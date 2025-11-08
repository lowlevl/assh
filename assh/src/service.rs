//! Service handling and requesting facilities.

use futures::Future;
use ssh_packet::arch::Ascii;

use crate::{Pipe, Session, side::Side};

// TODO: (feature) Handle multiple services at once ?

/// A _service handler_ in the transport protocol.
pub trait Handler {
    /// The errorneous outcome of the [`Handler`].
    type Err: From<crate::Error>;
    /// The successful outcome of the [`Handler`].
    type Ok<IO: Pipe, S: Side>;

    /// The handled service _identifier_.
    const SERVICE_NAME: Ascii<'static>;

    /// The service callback, this is called when we receive a service request from the peer.
    fn on_request<IO, S>(
        &mut self,
        session: Session<IO, S>,
    ) -> impl Future<Output = Result<Self::Ok<IO, S>, Self::Err>>
    where
        IO: Pipe,
        S: Side;
}

/// A _service request_ in the transport protocol.
pub trait Request {
    /// The errorneous outcome of the [`Request`].
    type Err: From<crate::Error>;
    /// The successful outcome of the [`Request`].
    type Ok<IO: Pipe, S: Side>;

    /// The requested service _identifier_.
    const SERVICE_NAME: Ascii<'static>;

    /// The service callback, this is called when the peer accepted the service request.
    fn on_accept<IO, S>(
        &mut self,
        session: Session<IO, S>,
    ) -> impl Future<Output = Result<Self::Ok<IO, S>, Self::Err>>
    where
        IO: Pipe,
        S: Side;
}
