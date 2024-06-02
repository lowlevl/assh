use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::trans;

use crate::{
    session::{Session, Side},
    Error,
};

/// A service request in the transport protocol.
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

/// Request a _service_ from the peer.
pub async fn request<I, S, R>(
    session: &mut Session<I, S>,
    mut service: R,
) -> Result<R::Ok<'_, I, S>, R::Err>
where
    I: AsyncBufRead + AsyncWrite + Unpin,
    S: Side,
    R: Request,
{
    session
        .send(&trans::ServiceRequest {
            service_name: R::SERVICE_NAME.into(),
        })
        .await?;

    let packet = session.recv().await?;
    if let Ok(trans::ServiceAccept { service_name }) = packet.to() {
        if &*service_name == R::SERVICE_NAME.as_bytes() {
            service.on_accept(session).await
        } else {
            session
                .disconnect(
                    trans::DisconnectReason::ServiceNotAvailable,
                    "Accepted service is unknown, aborting.",
                )
                .await?;

            Err(Error::UnknownService.into())
        }
    } else {
        session
            .disconnect(
                trans::DisconnectReason::ProtocolError,
                "Unexpected message outside of a service response, aborting.",
            )
            .await?;

        Err(Error::UnexpectedMessage.into())
    }
}
