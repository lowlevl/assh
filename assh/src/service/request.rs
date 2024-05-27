use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::trans;

use crate::{
    session::{Session, Side},
    Error, Result,
};

/// A service request in the transport protocol.
pub trait Request {
    /// Name of the service.
    const SERVICE_NAME: &'static str;

    /// Proceed with the accepted service from the peer.
    fn proceed(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin, impl Side>,
    ) -> impl Future<Output = Result<()>>;
}

/// Request a _service_ from the peer.
pub async fn request<R: Request>(
    session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin, impl Side>,
    mut requester: R,
) -> Result<()> {
    session
        .send(&trans::ServiceRequest {
            service_name: R::SERVICE_NAME.into(),
        })
        .await?;

    if &*session
        .recv()
        .await?
        .to::<trans::ServiceAccept>()?
        .service_name
        == R::SERVICE_NAME
    {
        requester.proceed(session).await
    } else {
        Err(Error::Protocol("Unexpected service in accept message"))
    }
}
