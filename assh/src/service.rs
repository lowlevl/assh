//! Service handling and requesting facilities.

use futures::Future;

use crate::{side::Side, Pipe, Session};

// TODO: Handle multiple services at once ?

/// A _service handler_ in the transport protocol.
pub trait Handler {
    /// The errorneous outcome of the [`Handler`].
    type Err: From<crate::Error>;
    /// The successful outcome of the [`Handler`].
    type Ok<'s, IO: Pipe + 's, S: Side + 's>;

    /// The handled service _identifier_.
    const SERVICE_NAME: &'static str;

    /// The service callback, this is called when we receive a service request from the peer.
    fn on_request<'s, IO, S>(
        &mut self,
        session: &'s mut Session<IO, S>,
    ) -> impl Future<Output = Result<Self::Ok<'s, IO, S>, Self::Err>>
    where
        IO: Pipe,
        S: Side;
}

/// A _service request_ in the transport protocol.
pub trait Request {
    /// The errorneous outcome of the [`Request`].
    type Err: From<crate::Error>;
    /// The successful outcome of the [`Request`].
    type Ok<'s, IO: Pipe + 's, S: Side + 's>;

    /// The requested service _identifier_.
    const SERVICE_NAME: &'static str;

    /// The service callback, this is called when the peer accepted the service request.
    fn on_accept<'s, IO, S>(
        &mut self,
        session: &'s mut Session<IO, S>,
    ) -> impl Future<Output = Result<Self::Ok<'s, IO, S>, Self::Err>>
    where
        IO: Pipe,
        S: Side;
}
