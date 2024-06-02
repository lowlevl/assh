use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::trans;

use crate::{
    session::{Session, Side},
    Error,
};

// TODO: Handle multiple services at once ?

/// A service handler in the transport protocol.
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

/// Handle _services_ from the peer.
pub async fn handle<I, S, H>(
    session: &mut Session<I, S>,
    mut service: H,
) -> Result<H::Ok<'_, I, S>, H::Err>
where
    I: AsyncBufRead + AsyncWrite + Unpin,
    S: Side,
    H: Handler,
{
    let packet = session.recv().await?;

    if let Ok(trans::ServiceRequest { service_name }) = packet.to() {
        if &*service_name == H::SERVICE_NAME.as_bytes() {
            session.send(&trans::ServiceAccept { service_name }).await?;

            service.on_request(session).await
        } else {
            session
                .disconnect(
                    trans::DisconnectReason::ServiceNotAvailable,
                    "Requested service is unknown, aborting.",
                )
                .await?;

            Err(Error::UnknownService.into())
        }
    } else {
        session
            .disconnect(
                trans::DisconnectReason::ProtocolError,
                "Unexpected message outside of a service request, aborting.",
            )
            .await?;

        Err(Error::UnexpectedMessage.into())
    }
}
