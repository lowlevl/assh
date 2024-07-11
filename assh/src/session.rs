use either::Either;
use futures::{AsyncBufRead, AsyncWrite, AsyncWriteExt};
use futures_time::future::FutureExt;
use ssh_packet::{
    arch::StringUtf8,
    trans::{
        Debug, Disconnect, DisconnectReason, Ignore, KexInit, ServiceAccept, ServiceRequest,
        Unimplemented,
    },
    Id, IntoPacket, Packet,
};

use crate::{
    error::{DisconnectedBy, DisconnectedError, Error, Result},
    service,
    side::Side,
    stream::Stream,
};

// TODO: Handle extension negotiation described in RFC8308

/// A trait alias for something _pipe-alike_, implementing [`AsyncBufRead`] and [`AsyncWrite`].
pub trait Pipe: AsyncBufRead + AsyncWrite + Unpin + Send + Sync + 'static {}
impl<T: AsyncBufRead + AsyncWrite + Unpin + Send + Sync + 'static> Pipe for T {}

/// A session wrapping a `stream` to handle **key-exchange** and **[`SSH-TRANS`]** layer messages.
pub struct Session<IO: Pipe, S: Side> {
    stream: Either<Stream<IO>, DisconnectedError>,
    config: S,

    peer_id: Id,
}

impl<IO, S> Session<IO, S>
where
    IO: Pipe,
    S: Side,
{
    /// Create a new [`Session`] from a [`Pipe`] stream,
    /// and some configuration.
    pub async fn new(mut stream: IO, config: S) -> Result<Self> {
        config.id().to_async_writer(&mut stream).await?;
        stream.flush().await?;

        let peer_id = Id::from_async_reader(&mut stream)
            .timeout(config.timeout())
            .await??;

        let stream = Stream::new(stream, config.timeout());

        tracing::debug!("Session started with peer `{peer_id}`");

        Ok(Self {
            stream: Either::Left(stream),
            config,
            peer_id,
        })
    }

    /// Access the [`Id`] of the connected peer.
    pub fn peer_id(&self) -> &Id {
        &self.peer_id
    }

    /// Access initial exchange hash.
    pub fn session_id(&self) -> Option<&[u8]> {
        self.stream.as_ref().left().and_then(Stream::session_id)
    }

    /// Waits until the [`Session`] becomes readable,
    /// mainly to be used with [`Session::recv`] in [`futures::select`],
    /// since the `recv` method is **not cancel-safe**.
    pub async fn readable(&mut self) -> Result<()> {
        let stream = match &mut self.stream {
            Either::Left(stream) => stream,
            Either::Right(err) => return Err(err.clone().into()),
        };

        stream.fill_buf().await
    }

    /// Receive a _packet_ from the connected peer.
    ///
    /// # Cancel safety
    /// This method is **not cancel-safe**, if used within a [`futures::select`] call,
    /// some data may be partially received.
    pub async fn recv(&mut self) -> Result<Packet> {
        loop {
            let stream = match &mut self.stream {
                Either::Left(stream) => stream,
                Either::Right(err) => return Err(err.clone().into()),
            };

            if stream.is_rekeyable() || stream.peek().await?.to::<KexInit>().is_ok() {
                if let Err(err) = self.config.kex(stream, &self.peer_id).await {
                    return Err(self
                        .disconnect(DisconnectReason::KeyExchangeFailed, err.to_string())
                        .await
                        .into());
                }

                continue;
            }

            let packet = stream.recv().await?;

            if let Ok(Disconnect {
                reason,
                description,
                ..
            }) = packet.to()
            {
                tracing::warn!("Peer disconnected with `{reason:?}`: {}", &*description);

                self.stream = Either::Right(DisconnectedError {
                    by: DisconnectedBy::Them,
                    reason,
                    description: description.into_string(),
                });
            } else if let Ok(Ignore { data }) = packet.to() {
                tracing::debug!("Received an 'ignore' message with length {}", data.len());
            } else if let Ok(Unimplemented { seq }) = packet.to() {
                tracing::debug!("Received an 'unimplemented' message about packet #{seq}",);
            } else if let Ok(Debug { message, .. }) = packet.to() {
                tracing::debug!("Received a 'debug' message: {}", &*message);
            } else {
                break Ok(packet);
            }
        }
    }

    /// Send a _packet_ to the connected peer.
    pub async fn send(&mut self, message: impl IntoPacket) -> Result<()> {
        let stream = match &mut self.stream {
            Either::Left(stream) => stream,
            Either::Right(err) => return Err(err.clone().into()),
        };

        if stream.is_rekeyable()
            || (stream.is_readable().await? && stream.peek().await?.to::<KexInit>().is_ok())
        {
            if let Err(err) = self.config.kex(stream, &self.peer_id).await {
                return Err(self
                    .disconnect(DisconnectReason::KeyExchangeFailed, err.to_string())
                    .await
                    .into());
            }
        }

        stream.send(message).await
    }

    /// Send a _disconnect message_ to the peer and shutdown the session.
    pub async fn disconnect(
        &mut self,
        reason: DisconnectReason,
        description: impl Into<StringUtf8>,
    ) -> DisconnectedError {
        let stream = match &mut self.stream {
            Either::Left(stream) => stream,
            Either::Right(err) => return err.clone(),
        };

        let message = Disconnect {
            reason,
            description: description.into(),
            language: Default::default(),
        };
        if let Err(Error::Disconnected(err)) = stream.send(&message).await {
            return err;
        }

        let err = DisconnectedError {
            by: DisconnectedBy::Us,
            reason: message.reason,
            description: message.description.into_string(),
        };
        self.stream = Either::Right(err.clone());

        err
    }

    /// Handle a _service_ for the peer.
    pub async fn handle<H>(mut self, mut service: H) -> Result<H::Ok<IO, S>, H::Err>
    where
        H: service::Handler,
    {
        let packet = self.recv().await?;

        if let Ok(ServiceRequest { service_name }) = packet.to() {
            if &*service_name == H::SERVICE_NAME.as_bytes() {
                self.send(&ServiceAccept { service_name }).await?;

                service.on_request(self).await
            } else {
                Err(Error::from(
                    self.disconnect(
                        DisconnectReason::ServiceNotAvailable,
                        "Requested service is unknown",
                    )
                    .await,
                )
                .into())
            }
        } else {
            Err(Error::from(
                self.disconnect(
                    DisconnectReason::ProtocolError,
                    "Unexpected message outside of a service request",
                )
                .await,
            )
            .into())
        }
    }

    /// Request a _service_ from the peer.
    pub async fn request<R>(mut self, mut service: R) -> Result<R::Ok<IO, S>, R::Err>
    where
        R: service::Request,
    {
        self.send(&ServiceRequest {
            service_name: R::SERVICE_NAME.into(),
        })
        .await?;

        let packet = self.recv().await?;
        if let Ok(ServiceAccept { service_name }) = packet.to() {
            if &*service_name == R::SERVICE_NAME.as_bytes() {
                service.on_accept(self).await
            } else {
                Err(Error::from(
                    self.disconnect(
                        DisconnectReason::ServiceNotAvailable,
                        "Accepted service is unknown",
                    )
                    .await,
                )
                .into())
            }
        } else {
            Err(Error::from(
                self.disconnect(
                    DisconnectReason::ProtocolError,
                    "Unexpected message outside of a service response",
                )
                .await,
            )
            .into())
        }
    }
}

impl<IO, S> Drop for Session<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn drop(&mut self) {
        // TODO: Find out: 1. if this blocking call is an issue; 2. how to have a generic way to trigger an async task regardless of the executor
        let err = futures::executor::block_on(
            self.disconnect(DisconnectReason::ByApplication, "user closed the session"),
        );

        tracing::debug!("Session closed with peer `{}`: {err}", self.peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::side::{client::Client, server::Server};

    use async_std::net::TcpStream;
    use futures::io::BufReader;

    #[test]
    fn assert_session_is_send() {
        fn is_send<T: Send>() {}

        is_send::<Session<BufReader<TcpStream>, Client>>();
        is_send::<Session<BufReader<TcpStream>, Server>>();
    }

    #[test]
    fn assert_session_is_sync() {
        fn is_sync<T: Sync>() {}

        is_sync::<Session<BufReader<TcpStream>, Client>>();
        is_sync::<Session<BufReader<TcpStream>, Server>>();
    }
}
