use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::trans;

use crate::{
    session::{Session, Side},
    Error, Result,
};

/// A service request in the transport protocol.
pub trait Request {
    /// Name of the requested service.
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

    let packet = session.recv().await?;
    if let Ok(trans::ServiceAccept { service_name }) = packet.to() {
        if &*service_name == R::SERVICE_NAME.as_bytes() {
            requester.proceed(session).await
        } else {
            session
                .disconnect(
                    trans::DisconnectReason::ServiceNotAvailable,
                    "Accepted service is unknown, aborting.",
                )
                .await?;

            Err(Error::UnknownService)
        }
    } else {
        session
            .disconnect(
                trans::DisconnectReason::ProtocolError,
                "Unexpected message outside of a service response, aborting.",
            )
            .await?;

        Err(Error::UnexpectedMessage)
    }
}
