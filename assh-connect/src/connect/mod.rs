//! Facilities to interract with the SSH _connect_ protocol.

use assh::{side::Side, Pipe};
use dashmap::DashSet;
use futures::{task, TryStream};
use ssh_packet::connect;

use crate::{
    channel::{self, LocalWindow},
    channel_open, global_request,
    mux::{Interest, Mux},
    Error, Result,
};

mod service;
pub use service::Service;

// TODO: Flush Poller Sink on Drop ?

/// A wrapper around [`assh::Session`] to interract with the connect layer.
pub struct Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(crate) mux: Mux<IO, S>,
    channels: DashSet<u32>,
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

        self.mux.register(interest);
        let unregister_on_drop = defer::defer(move || self.mux.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Connect::global_requests").entered();

            self.mux
                .poll_interest(cx, &interest)
                .map_ok(|packet| {
                    global_request::GlobalRequest::new(&self.mux, packet.to().unwrap())
                })
                .map_err(Into::into)
        })
    }

    // TODO: Compact `Self::global_request`, `Self::global_request_wait` with a trait ?

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
        self.mux.register(interest);

        let with_port = matches!(context, connect::GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

        self.mux
            .send(&connect::GlobalRequest {
                want_reply: false.into(),
                context,
            })
            .await?;

        let response = futures::future::poll_fn(|cx| {
            let response =
                futures::ready!(self.mux.poll_interest(cx, &interest)).and_then(|packet| {
                    match packet {
                        Ok(packet) => {
                            if !with_port && packet.to::<connect::RequestSuccess>().is_ok() {
                                Some(Ok(global_request::Response::Success(None)))
                            } else if let Ok(connect::ForwardingSuccess { bound_port }) =
                                packet.to()
                            {
                                Some(Ok(global_request::Response::Success(Some(bound_port))))
                            } else if packet.to::<connect::RequestFailure>().is_ok() {
                                Some(Ok(global_request::Response::Failure))
                            } else {
                                None
                            }
                        }
                        Err(err) => Some(Err(err)),
                    }
                });

            task::Poll::Ready(response)
        })
        .await
        .ok_or(Error::ChannelClosed);

        self.mux.unregister(&interest);

        Ok(response??)
    }

    pub(crate) fn local_id(&self) -> u32 {
        // TODO: Assess the need for this loop
        loop {
            let id = self
                .channels
                .iter()
                .map(|id| *id + 1)
                .max()
                .unwrap_or_default();

            if self.channels.insert(id) {
                break id;
            }
        }
    }

    /// Iterate over the incoming _channel open requests_.
    pub fn channel_opens(
        &self,
    ) -> impl TryStream<Ok = channel_open::ChannelOpen<'_, IO, S>, Error = crate::Error> + '_ {
        let interest = Interest::ChannelOpenRequest;

        self.mux.register(interest);
        let unregister_on_drop = defer::defer(move || self.mux.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Connect::channel_opens").entered();

            self.mux
                .poll_interest(cx, &interest)
                .map_ok(|packet| {
                    channel_open::ChannelOpen::new(&self.mux, self.local_id(), packet.to().unwrap())
                })
                .map_err(Into::into)
        })
    }

    /// Send a _channel open request_, and wait for it's response to return an opened channel.
    pub async fn channel_open(
        &self,
        context: connect::ChannelOpenContext,
    ) -> Result<channel_open::Response<'_, IO, S>> {
        // TODO: Release the id eventually if the request is rejected
        let local_id = self.local_id();

        let interest = Interest::ChannelOpenResponse(local_id);
        self.mux.register(interest);

        self.mux
            .send(&connect::ChannelOpen {
                sender_channel: local_id,
                initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
                context,
            })
            .await?;

        let response = futures::future::poll_fn(|cx| {
            let response =
                futures::ready!(self.mux.poll_interest(cx, &interest)).and_then(|packet| {
                    match packet {
                        Ok(packet) => {
                            if let Ok(message) = packet.to::<connect::ChannelOpenConfirmation>() {
                                Some(Ok(channel_open::Response::Success(channel::Channel::new(
                                    &self.mux,
                                    local_id,
                                    message.sender_channel,
                                    message.initial_window_size,
                                    message.maximum_packet_size,
                                ))))
                            } else if let Ok(message) = packet.to::<connect::ChannelOpenFailure>() {
                                Some(Ok(channel_open::Response::Failure {
                                    reason: message.reason,
                                    description: message.description.into_string(),
                                }))
                            } else {
                                None
                            }
                        }
                        Err(err) => Some(Err(err)),
                    }
                });

            task::Poll::Ready(response)
        })
        .await
        .ok_or(Error::ChannelClosed);

        self.mux.unregister(&interest);

        Ok(response??)
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
