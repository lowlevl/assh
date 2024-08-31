//! Facilities to interract with the SSH _connect_ protocol.

use assh::{side::Side, Pipe};
use dashmap::DashSet;
use futures::{task, TryStream};
use ssh_packet::{binrw, connect};

use crate::{
    channel::{self, LocalWindow},
    channel_open, global_request,
    mux::{Interest, Mux},
    Error, Result,
};

mod service;
pub use service::Service;

// TODO: (reliability) Flush Poller Sink on Drop ?

/// A wrapper around [`assh::Session`] to interract with the connect layer.
pub struct Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(crate) mux: Mux<IO, S>,

    // TODO: (compliance/reliability) Maybe replace this set with a `sharded-slab::Slab` to track dropped channels.
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
        self.mux.register(interest);

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

        let result = futures::future::poll_fn(|cx| {
            if !with_port {
                let polled = futures::ready!(self.mux.poll_interest(cx, &interest)).transpose()?;

                task::Poll::Ready(match polled {
                    Some(Response::Success(_)) => {
                        let response = global_request::Response::Success(None);

                        Some(Ok::<_, assh::Error>(response))
                    }

                    Some(Response::Failure(_)) => {
                        let response = global_request::Response::Failure;

                        Some(Ok(response))
                    }

                    _ => None,
                })
            } else {
                let polled = futures::ready!(self.mux.poll_interest(cx, &interest)).transpose()?;

                task::Poll::Ready(match polled {
                    Some(ResponsePort::Success(message)) => {
                        let response = global_request::Response::Success(Some(message.bound_port));

                        Some(Ok::<_, assh::Error>(response))
                    }

                    Some(ResponsePort::Failure(_)) => {
                        let response = global_request::Response::Failure;

                        Some(Ok(response))
                    }

                    _ => None,
                })
            }
        })
        .await
        .ok_or(Error::ChannelClosed);

        self.mux.unregister(&interest);

        Ok(result??)
    }

    pub(crate) fn local_id(&self) -> u32 {
        // TODO: (optimization) Assess the need for this loop
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
                .map_ok(|inner| channel_open::ChannelOpen::new(&self.mux, inner, self.local_id()))
                .map_err(Into::into)
        })
    }

    /// Send a _channel open request_, and wait for it's response to return an opened channel.
    pub async fn channel_open(
        &self,
        context: connect::ChannelOpenContext,
    ) -> Result<channel_open::Response<'_, IO, S>> {
        // TODO: (reliability) Release the id eventually if the request is rejected
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

        #[binrw::binrw]
        #[br(little)]
        enum Response {
            Success(connect::ChannelOpenConfirmation),
            Failure(connect::ChannelOpenFailure),
        }

        let result = futures::future::poll_fn(|cx| {
            let polled = futures::ready!(self.mux.poll_interest(cx, &interest)).transpose()?;

            task::Poll::Ready(match polled {
                Some(Response::Success(message)) => {
                    let response = channel_open::Response::Success(channel::Channel::new(
                        &self.mux,
                        local_id,
                        message.sender_channel,
                        message.initial_window_size,
                        message.maximum_packet_size,
                    ));

                    Some(Ok::<_, assh::Error>(response))
                }

                Some(Response::Failure(message)) => {
                    let response = channel_open::Response::Failure {
                        reason: message.reason,
                        description: message.description.into_string(),
                    };

                    Some(Ok(response))
                }

                _ => None,
            })
        })
        .await
        .ok_or(Error::ChannelClosed);

        self.mux.unregister(&interest);

        Ok(result??)
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
