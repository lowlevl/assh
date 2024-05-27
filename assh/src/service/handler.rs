use futures::{AsyncBufRead, AsyncWrite, Future};

use crate::{
    session::{Session, Side},
    Result,
};

/// A service handler in the transport protocol.
pub trait Handler {
    /// Name of the service.
    const SERVICE_NAME: &'static str;

    /// Proceed with the service request from the peer.
    fn proceed(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin + Send, impl Side>,
    ) -> impl Future<Output = Result<()>>;
}

/// Handle _services_ from the peer.
pub fn handle() {}
