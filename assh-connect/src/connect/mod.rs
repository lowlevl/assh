//! Facilities to interract with the SSH _connect_ protocol.

use assh::{side::Side, Pipe};
use futures::{FutureExt, TryStream};
use ssh_packet::{binrw, connect};

use crate::{
    channel::{self, LocalWindow},
    channel_open, global_request,
    mux::{Interest, Mux},
    slots::Slots,
    Error, Result,
};

mod service;
pub use service::Service;

// TODO: (reliability) Flush Poller Sink on Drop ?

const CHANNEL_MAX_COUNT: usize = 8;

/// A wrapper around [`assh::Session`] to interract with the connect layer.
pub struct Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(crate) mux: Mux<IO, S>,
    channels: Slots<u32, CHANNEL_MAX_COUNT>,
}

impl<IO, S> Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn new(session: assh::Session<IO, S>) -> Self {
        Self {
            mux: Mux::from(session),
            channels: Default::default(),
        }
    }

    /// Iterate over the incoming _global requests_.
    pub fn global_requests(
        &self,
    ) -> impl TryStream<Ok = global_request::GlobalRequest<'_, IO, S>, Error = crate::Error> + '_
    {
        let interest = Interest::GlobalRequest;
        let unregister_on_drop = self.mux.register_scoped(interest);

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Connect::global_requests").entered();

            self.mux
                .poll_interest(cx, &interest)
                .map_ok(|inner| global_request::GlobalRequest::new(&self.mux, inner))
                .map_err(Into::into)
        })
    }

    // TODO: (ux) Compact `Self::global_request`, `Self::global_request_wait` with a trait ?

    /// Send a _global request_.
    pub async fn global_request(&self, context: connect::GlobalRequestContext) -> Result<()> {
        self.mux
            .send(&connect::GlobalRequest {
                want_reply: false.into(),
                context,
            })
            .await?;

        Ok(())
    }

    /// Send a _global request_, and wait for it's response.
    pub async fn global_request_wait(
        &self,
        context: connect::GlobalRequestContext,
    ) -> Result<global_request::Response> {
        let interest = Interest::GlobalResponse;
        let _unregister_on_drop = self.mux.register_scoped(interest);

        let with_port = matches!(context, connect::GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

        self.mux
            .send(&connect::GlobalRequest {
                want_reply: false.into(),
                context,
            })
            .await?;

        #[binrw::binrw]
        #[br(little)]
        enum Response {
            Success(connect::RequestSuccess),
            Failure(connect::RequestFailure),
        }

        #[binrw::binrw]
        #[br(little)]
        enum ResponsePort {
            Success(connect::ForwardingSuccess),
            Failure(connect::RequestFailure),
        }

        if !with_port {
            futures::future::poll_fn(|cx| self.mux.poll_interest::<Response>(cx, &interest))
                .map(|polled| match polled.transpose()? {
                    Some(Response::Success(_)) => Ok(global_request::Response::Success(None)),
                    Some(Response::Failure(_)) => Ok(global_request::Response::Failure),
                    _ => Err(Error::ChannelClosed),
                })
                .await
        } else {
            futures::future::poll_fn(|cx| self.mux.poll_interest::<ResponsePort>(cx, &interest))
                .map(|polled| match polled.transpose()? {
                    Some(ResponsePort::Success(message)) => {
                        Ok(global_request::Response::Success(Some(message.bound_port)))
                    }
                    Some(ResponsePort::Failure(_)) => Ok(global_request::Response::Failure),
                    _ => Err(Error::SessionClosed),
                })
                .await
        }
    }

    /// Iterate over the incoming _channel open requests_.
    pub fn channel_opens(
        &self,
    ) -> impl TryStream<Ok = channel_open::ChannelOpen<'_, IO, S>, Error = crate::Error> + '_ {
        let interest = Interest::ChannelOpenRequest;
        let unregister_on_drop = self.mux.register_scoped(interest);

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Connect::channel_opens").entered();

            self.mux
                .poll_interest(cx, &interest)
                .map_ok(|inner: connect::ChannelOpen| {
                    let id = self
                        .channels
                        .insert(inner.sender_channel)
                        .ok_or(Error::TooManyChannels)?
                        .into();

                    Ok::<_, crate::Error>(channel_open::ChannelOpen::new(&self.mux, inner, id))
                })
                .map(|polled| polled.map(|result| result?))
        })
    }

    /// Send a _channel open request_, and wait for it's response to return an opened channel.
    pub async fn channel_open(
        &self,
        context: connect::ChannelOpenContext,
    ) -> Result<channel_open::Response<'_, IO, S>> {
        let Some(reserved) = self.channels.reserve() else {
            return Err(Error::TooManyChannels);
        };

        let interest = Interest::ChannelOpenResponse(reserved.index() as u32);
        let _unregister_on_drop = self.mux.register_scoped(interest);

        self.mux
            .send(&connect::ChannelOpen {
                sender_channel: reserved.index() as u32,
                initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
                context,
            })
            .await?;

        #[binrw::binrw]
        #[br(little)]
        enum Response {
            Success(connect::ChannelOpenConfirmation),
            Failure(connect::ChannelOpenFailure),
        }

        futures::future::poll_fn(|cx| self.mux.poll_interest::<Response>(cx, &interest))
            .map(|polled| match polled.transpose()? {
                Some(Response::Success(message)) => {
                    let id = reserved.into_lease(message.sender_channel);

                    Ok(channel_open::Response::Success(channel::Channel::new(
                        &self.mux,
                        id.into(),
                        message.initial_window_size,
                        message.maximum_packet_size,
                    )))
                }
                Some(Response::Failure(message)) => Ok(channel_open::Response::Failure {
                    reason: message.reason,
                    description: message.description.into_string(),
                }),
                _ => Err(Error::SessionClosed),
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assh::side::{client::Client, server::Server};
    use async_compat::Compat;
    use futures::io::BufReader;
    use tokio::net::TcpStream;

    #[test]
    fn assert_connect_is_send() {
        fn is_send<T: Send>() {}

        is_send::<Connect<BufReader<Compat<TcpStream>>, Client>>();
        is_send::<Connect<BufReader<Compat<TcpStream>>, Server>>();
    }

    #[test]
    fn assert_connect_is_sync() {
        fn is_sync<T: Sync>() {}

        is_sync::<Connect<BufReader<Compat<TcpStream>>, Client>>();
        is_sync::<Connect<BufReader<Compat<TcpStream>>, Server>>();
    }
}
