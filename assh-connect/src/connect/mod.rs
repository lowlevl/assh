//! Facilities to interract with the SSH _connect_ protocol.

use assh::{side::Side, Pipe, Session};
use dashmap::{DashMap, DashSet};
use futures::{
    lock::{Mutex, MutexGuard},
    task::{self, AtomicWaker},
    FutureExt, SinkExt, Stream, TryStream,
};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{Error, Result};

mod poller;
use poller::Poller;

mod interest;
pub(crate) use interest::Interest;

pub mod channel_open;
pub mod global_request;

#[doc(no_inline)]
pub use connect::{ChannelOpenContext, ChannelOpenFailureReason, GlobalRequestContext};

/// A wrapper around a [`Session`] to interract with the connect layer.
pub struct Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(crate) poller: Mutex<Poller<IO, S>>,
    pub(crate) channels: DashSet<u32>,

    interests: DashMap<Interest, AtomicWaker>,
    buffer: Mutex<Option<Packet>>,
}

impl<IO, S> Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(crate) fn new(session: Session<IO, S>) -> Self {
        Self {
            poller: Mutex::new(Poller::from(session)),
            channels: Default::default(),

            interests: Default::default(),
            buffer: Default::default(),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut task::Context,
    ) -> task::Poll<assh::Result<MutexGuard<'_, Option<Packet>>>> {
        let mut buffer = futures::ready!(self.buffer.lock().poll_unpin(cx));

        if buffer.is_none() {
            let poller = futures::ready!(self.poller.lock().poll_unpin(cx));
            let mut poller = std::pin::Pin::new(poller);

            if let Some(res) = futures::ready!(poller.as_mut().poll_next(cx)) {
                *buffer = Some(res?);
            }
        }

        task::Poll::Ready(Ok(buffer))
    }

    pub(crate) fn poll_take(
        &self,
        cx: &mut task::Context,
        interest: &Interest,
    ) -> task::Poll<Option<assh::Result<Packet>>> {
        if let Some(waker) = self.interests.get(interest) {
            waker.register(cx.waker());
        } else {
            tracing::trace!("Polled for unregistered `{interest:?}` interest, returning None");

            return task::Poll::Ready(None);
        }

        let mut buffer = futures::ready!(self.poll_recv(cx))?;

        tracing::trace!("Polling incoming data for `{interest:?}`");

        match buffer.take() {
            None => {
                tracing::trace!("Receiver is dead, waking up all awaiting tasks");

                for waker in self.interests.iter() {
                    waker.wake();
                }

                task::Poll::Ready(None)
            }
            Some(packet) => {
                let packet_interest = Interest::from(&packet);

                if interest == &packet_interest {
                    tracing::trace!("Interest `{interest:?}` matched, popping packet");

                    task::Poll::Ready(Some(Ok(packet)))
                } else {
                    match self.interests.get(&packet_interest) {
                        Some(waker) => {
                            tracing::trace!(
                                "Interest unmatched, storing packet and waking task for: {packet_interest:?}"
                            );

                            *buffer = Some(packet);

                            waker.wake();
                            task::Poll::Pending
                        }
                        None => {
                            tracing::warn!("Dropped {}bytes because interest was unregistered for `{packet_interest:?}`", packet.payload.len());

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

    pub(crate) fn unregister_if(&self, filter: impl FnMut(&Interest) -> bool) {
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

    /// Send a _global request_.
    pub async fn global_request(&self, context: GlobalRequestContext) -> Result<()> {
        self.poller
            .lock()
            .await
            .send(
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
        context: GlobalRequestContext,
    ) -> Result<global_request::Response> {
        let interest = Interest::GlobalResponse;
        self.register(interest);

        let with_port = matches!(context, GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

        self.poller
            .lock()
            .await
            .send(
                connect::GlobalRequest {
                    want_reply: false.into(),
                    context,
                }
                .into_packet(),
            )
            .await?;

        let response = futures::future::poll_fn(|cx| {
            let polled = futures::ready!(self.poll_take(cx, &interest));
            let response = polled.and_then(|packet| match packet {
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

    /// Iterate over the incoming _global requests_ from the peer.
    pub fn global_requests(
        &self,
    ) -> impl TryStream<Ok = global_request::GlobalRequest<'_, IO, S>, Error = crate::Error> + '_
    {
        let interest = Interest::GlobalRequest;

        self.register(interest);
        let unregister_on_drop = defer::defer(move || self.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;

            self.poll_take(cx, &interest)
                .map_ok(|packet| global_request::GlobalRequest::new(self, packet.to().unwrap()))
                .map_err(Into::into)
        })
    }

    // /// Request a new _channel_ with the provided `context`.
    // pub async fn channel_open(
    //     &mut self,
    //     context: ChannelOpenContext,
    // ) -> Result<channel_open::ChannelOpen> {
    //     let local_id = self.local_id();

    //     self.session
    //         .lock()
    //         .await
    //         .send(&connect::ChannelOpen {
    //             sender_channel: local_id,
    //             initial_window_size: channel::LocalWindow::INITIAL_WINDOW_SIZE,
    //             maximum_packet_size: channel::LocalWindow::MAXIMUM_PACKET_SIZE,
    //             context,
    //         })
    //         .await?;

    //     let packet = self.session.lock().await.recv().await?;

    //     if let Ok(open_failure) = packet.to::<connect::ChannelOpenFailure>() {
    //         if open_failure.recipient_channel == local_id {
    //             Ok(channel_open::ChannelOpen::Rejected {
    //                 reason: open_failure.reason,
    //                 message: open_failure.description.into_string(),
    //             })
    //         } else {
    //             Err(assh::Error::UnexpectedMessage.into())
    //         }
    //     } else if let Ok(open_confirmation) = packet.to::<connect::ChannelOpenConfirmation>() {
    //         if open_confirmation.recipient_channel == local_id {
    //             let (channel, handle) = channel::pair(
    //                 open_confirmation.recipient_channel,
    //                 open_confirmation.maximum_packet_size,
    //                 (
    //                     channel::LocalWindow::default(),
    //                     channel::RemoteWindow::from(open_confirmation.initial_window_size),
    //                 ),
    //                 self.outgoing.0.clone(),
    //             );

    //             self.channels.insert(local_id, handle);

    //             Ok(channel_open::ChannelOpen::Accepted(channel))
    //         } else {
    //             Err(assh::Error::UnexpectedMessage.into())
    //         }
    //     } else {
    //         Err(assh::Error::UnexpectedMessage.into())
    //     }
    // }

    /// Iterate over the incoming _channel open requests_ from the peer.
    pub fn channel_opens(
        &self,
    ) -> impl TryStream<Ok = channel_open::ChannelOpen<'_, IO, S>, Error = crate::Error> + '_ {
        let interest = Interest::ChannelOpen;

        self.register(interest);
        let unregister_on_drop = defer::defer(move || self.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;

            self.poll_take(cx, &interest)
                .map_ok(|packet| channel_open::ChannelOpen::new(self, packet.to().unwrap()))
                .map_err(Into::into)
        })
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
