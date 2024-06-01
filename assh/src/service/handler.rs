use futures::{AsyncBufRead, AsyncWrite, Future};
use ssh_packet::{arch, trans};

use crate::{
    session::{Session, Side},
    Error, Result,
};

mod private {
    pub trait Sealed {}

    impl Sealed for () {}
    impl<T: super::Handler> Sealed for T {}
    impl<T0: super::Handlers, T1: super::Handlers> Sealed for (T0, T1) {}
}

/// One or more service handlers, combinable with tuples.
pub trait Handlers: private::Sealed {
    /// Proceed with the service request from the peer, if the service name matches.
    fn proceed<I: AsyncBufRead + AsyncWrite + Unpin, S: Side>(
        &mut self,
        session: &mut Session<I, S>,
        service_name: arch::Bytes,
    ) -> impl Future<Output = Result<()>>;
}

impl Handlers for () {
    async fn proceed<I: AsyncBufRead + AsyncWrite + Unpin, S: Side>(
        &mut self,
        _: &mut Session<I, S>,
        _: arch::Bytes,
    ) -> Result<()> {
        Err(Error::UnknownService)
    }
}

impl<H0: Handlers, H1: Handlers> Handlers for (H0, H1) {
    async fn proceed<I: AsyncBufRead + AsyncWrite + Unpin, S: Side>(
        &mut self,
        session: &mut Session<I, S>,
        service_name: arch::Bytes,
    ) -> Result<()> {
        match self.0.proceed(session, service_name.clone()).await {
            Err(Error::UnknownService) => self.1.proceed(session, service_name).await,
            other => other,
        }
    }
}

/// A service handler in the transport protocol.
pub trait Handler {
    /// Name of the handled service.
    const SERVICE_NAME: &'static str;

    /// Proceed with the service request from the peer.
    fn handle<I: AsyncBufRead + AsyncWrite + Unpin, S: Side>(
        &mut self,
        session: &mut Session<I, S>,
    ) -> impl Future<Output = Result<()>>;
}

impl<H: Handler> Handlers for H {
    async fn proceed<I: AsyncBufRead + AsyncWrite + Unpin, S: Side>(
        &mut self,
        session: &mut Session<I, S>,
        service_name: arch::Bytes,
    ) -> Result<()> {
        if &*service_name == H::SERVICE_NAME.as_bytes() {
            session.send(&trans::ServiceAccept { service_name }).await?;

            self.handle(session).await
        } else {
            Err(Error::UnknownService)
        }
    }
}

/// Handle _services_ from the peer.
pub async fn handle<I: AsyncBufRead + AsyncWrite + Unpin, S: Side, H: Handlers>(
    session: &mut Session<I, S>,
    mut handlers: H,
) -> Result<()> {
    let packet = session.recv().await?;

    if let Ok(trans::ServiceRequest { service_name }) = packet.to() {
        match handlers.proceed(session, service_name).await {
            err @ Err(Error::UnknownService) => {
                session
                    .disconnect(
                        trans::DisconnectReason::ServiceNotAvailable,
                        "Requested service is unknown, aborting.",
                    )
                    .await?;

                err
            }
            other => other,
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
