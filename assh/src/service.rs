//! Service handling facilities for [`session::Session`].

use futures::{AsyncBufRead, AsyncWrite, Future};

use crate::session::{Session, Side};

#[cfg(doc)]
use crate::session;

// TODO: Handle multiple services at once ?

/// A _service handler_ in the transport protocol.
pub trait Handler {
    /// The errorneous outcome of the [`Handler`].
    type Err: From<crate::Error>;
    /// The successful outcome of the [`Handler`].
    type Ok<'s, I: 's, S: 's>;

    /// The handled service _identifier_.
    const SERVICE_NAME: &'static str;

    /// The service callback, this is called when we receive a service request from the peer.
    fn on_request<'s, I, S>(
        &mut self,
        session: &'s mut Session<I, S>,
    ) -> impl Future<Output = Result<Self::Ok<'s, I, S>, Self::Err>>
    where
        I: AsyncBufRead + AsyncWrite + Unpin,
        S: Side;
}

/// A _service request_ in the transport protocol.
pub trait Request {
    /// The errorneous outcome of the [`Request`].
    type Err: From<crate::Error>;
    /// The successful outcome of the [`Request`].
    type Ok<'s, I: 's, S: 's>;

    /// The requested service _identifier_.
    const SERVICE_NAME: &'static str;

    /// The service callback, this is called when the peer accepted the service request.
    fn on_accept<'s, I, S>(
        &mut self,
        session: &'s mut Session<I, S>,
    ) -> impl Future<Output = Result<Self::Ok<'s, I, S>, Self::Err>>
    where
        I: AsyncBufRead + AsyncWrite + Unpin,
        S: Side;
}
