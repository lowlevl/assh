use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::trans;

use crate::{
    session::{Session, Side},
    Error, Result,
};

// TODO: Support handling multiple services at once.

/// A service handler in the transport protocol.
pub trait Handler {
    /// Name of the handled service.
    const SERVICE_NAME: &'static str;

    /// Proceed with the service request from the peer.
    fn proceed(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin, impl Side>,
    ) -> impl Future<Output = Result<()>>;
}

/// Handle _services_ from the peer.
pub async fn handle<H: Handler>(
    session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin, impl Side>,
    mut handler: H,
) -> Result<()> {
    let packet = session.recv().await?;

    if let Ok(trans::ServiceRequest { service_name }) = packet.to() {
        if &*service_name == H::SERVICE_NAME {
            session.send(&trans::ServiceAccept { service_name }).await?;

            handler.proceed(session).await
        } else {
            session
                .disconnect(
                    trans::DisconnectReason::ServiceNotAvailable,
                    "Requested service is unknown, aborting.",
                )
                .await?;

            Err(Error::UnknownService)
        }
    } else {
        session
            .disconnect(
                trans::DisconnectReason::ProtocolError,
                "Unexpected message outside of a service request, aborting.",
            )
            .await?;

        Err(Error::UnexpectedMessage)
    }
}
