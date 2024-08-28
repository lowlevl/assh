//! Facilities to interract with the SSH _connect_ protocol.

use assh::{side::Side, Pipe};
use dashmap::{DashMap, DashSet};
use futures::{lock::Mutex, task, FutureExt, SinkExt, TryStream};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{
    channel::{self, LocalWindow},
    channel_open, global_request,
    interest::Interest,
    poller::Poller,
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
    pub(crate) poller: Mutex<Poller<IO, S>>,
    pub(crate) channels: DashSet<u32>,

    interests: DashMap<Interest, task::AtomicWaker>,
}

impl<IO, S> Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn new(session: assh::Session<IO, S>) -> Self {
        Self {
            poller: Mutex::new(Poller::from(session)),
            channels: Default::default(),

            interests: Default::default(),
        }
    }

    // TODO: Move method to a separate structure.
    pub(crate) async fn send(&self, item: Packet) -> assh::Result<()> {
        self.poller.lock().await.feed(item).await?;

        futures::future::poll_fn(|cx| {
            let mut poller = futures::ready!(self.poller.lock().poll_unpin(cx));

            poller.poll_flush_unpin(cx)
        })
        .await
    }

    // TODO: Move method to a separate structure.
    pub(crate) fn poll_for(
        &self,
        cx: &mut task::Context,
        interest: &Interest,
    ) -> task::Poll<Option<assh::Result<Packet>>> {
        tracing::trace!("Polled with interest `{interest:?}`");

        if self
            .interests
            .get(interest)
            .as_deref()
            .map(|waker| waker.register(cx.waker()))
            .is_none()
        {
            tracing::trace!("{interest:?}: Polled for unregistered interest, returning `None`");

            return task::Poll::Ready(None);
        }

        let mut poller = futures::ready!(self.poller.lock().poll_unpin(cx));
        let buffer = futures::ready!(poller.poll_peek(cx))?;

        match buffer.take() {
            None => {
                tracing::trace!(
                    "{interest:?}: Receiver dead, unregistering all interests, waking up tasks"
                );

                // Optimization for woken up tasks to return early `Ready(None)`.
                self.unregister_if(|_| true);

                task::Poll::Ready(None)
            }
            Some(packet) => {
                let Some(packet_interest) = Interest::parse(&packet) else {
                    return task::Poll::Ready(Some(Err(assh::Error::UnexpectedMessage)));
                };

                if interest == &packet_interest {
                    tracing::trace!("{interest:?}: Matched, popping packet");

                    task::Poll::Ready(Some(Ok(packet)))
                } else {
                    match self.interests.get(&packet_interest).as_deref() {
                        Some(waker) => {
                            tracing::trace!("{interest:?} != {packet_interest:?}: Storing packet and waking task");

                            *buffer = Some(packet);
                            waker.wake();

                            task::Poll::Pending
                        }
                        None => {
                            tracing::warn!(
                                "!{packet_interest:?}: Dropping {}bytes, unregistered interest",
                                packet.payload.len()
                            );

                            // TODO: Respond to unhandled `GlobalRequest`, `ChannelOpenRequest` & `ChannelRequest` that *want_reply*.

                            cx.waker().wake_by_ref();
                            task::Poll::Pending
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn register(&self, interest: Interest) {
        // This is a genuine programming error from the user of the crate,
        // and could cause all sorts of runtime inconsistencies.
        #[allow(clippy::panic)]
        if self
            .interests
            .insert(interest, Default::default())
            .is_some()
        {
            panic!("Unable to register multiple concurrent interests for `{interest:?}`");
        }

        tracing::trace!("Registered interest for `{interest:?}`");
    }

    pub(crate) fn unregister(&self, interest: &Interest) {
        if let Some((interest, waker)) = self.interests.remove(interest) {
            tracing::trace!("Unregistered interest for `{interest:?}`");

            // Wake unregistered tasks to signal them to finish.
            waker.wake();
        }
    }

    pub(crate) fn unregister_if(&self, filter: impl Fn(&Interest) -> bool) {
        // NOTE: We collect here to remove reference to the DashMap
        // which would deadlock on calls to `remove` in `Self::unregister`.
        for interest in self
            .interests
            .iter()
            .map(|interest| *interest.key())
            .filter(filter)
            .collect::<Vec<_>>()
        {
            self.unregister(&interest);
        }
    }

    /// Iterate over the incoming _global requests_.
    pub fn global_requests(
        &self,
    ) -> impl TryStream<Ok = global_request::GlobalRequest<'_, IO, S>, Error = crate::Error> + '_
    {
        let interest = Interest::GlobalRequest;

        self.register(interest);
        let unregister_on_drop = defer::defer(move || self.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Connect::global_requests").entered();

            self.poll_for(cx, &interest)
                .map_ok(|packet| global_request::GlobalRequest::new(self, packet.to().unwrap()))
                .map_err(Into::into)
        })
    }

    // TODO: Compact `Self::global_request`, `Self::global_request_wait` with a trait ?

    /// Send a _global request_.
    pub async fn global_request(&self, context: connect::GlobalRequestContext) -> Result<()> {
        self.send(
            connect::GlobalRequest {
                want_reply: false.into(),
                context,
            }
            .into_packet(),
        )
        .await?;

        Ok(())
    }

    /// Send a _global request_, and wait for it's response.
    pub async fn global_request_wait(
        &self,
        context: connect::GlobalRequestContext,
    ) -> Result<global_request::Response> {
        let interest = Interest::GlobalResponse;
        self.register(interest);

        let with_port = matches!(context, connect::GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

        self.send(
            connect::GlobalRequest {
                want_reply: false.into(),
                context,
            }
            .into_packet(),
        )
        .await?;

        let response = futures::future::poll_fn(|cx| {
            let response =
                futures::ready!(self.poll_for(cx, &interest)).and_then(|packet| match packet {
                    Ok(packet) => {
                        if !with_port && packet.to::<connect::RequestSuccess>().is_ok() {
                            Some(Ok(global_request::Response::Success(None)))
                        } else if let Ok(connect::ForwardingSuccess { bound_port }) = packet.to() {
                            Some(Ok(global_request::Response::Success(Some(bound_port))))
                        } else if packet.to::<connect::RequestFailure>().is_ok() {
                            Some(Ok(global_request::Response::Failure))
                        } else {
                            None
                        }
                    }
                    Err(err) => Some(Err(err)),
                });

            task::Poll::Ready(response)
        })
        .await
        .ok_or(Error::ChannelClosed);

        self.unregister(&interest);

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

        self.register(interest);
        let unregister_on_drop = defer::defer(move || self.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Connect::channel_opens").entered();

            self.poll_for(cx, &interest)
                .map_ok(|packet| channel_open::ChannelOpen::new(self, packet.to().unwrap()))
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
        self.register(interest);

        self.send(
            connect::ChannelOpen {
                sender_channel: local_id,
                initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
                context,
            }
            .into_packet(),
        )
        .await?;

        let response = futures::future::poll_fn(|cx| {
            let response =
                futures::ready!(self.poll_for(cx, &interest)).and_then(|packet| match packet {
                    Ok(packet) => {
                        if let Ok(message) = packet.to::<connect::ChannelOpenConfirmation>() {
                            Some(Ok(channel_open::Response::Success(channel::Channel::new(
                                self,
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
                });

            task::Poll::Ready(response)
        })
        .await
        .ok_or(Error::ChannelClosed);

        self.unregister(&interest);

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
