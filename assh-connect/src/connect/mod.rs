//! Facilities to interract with the SSH _connect_ protocol.

use assh::{side::Side, Pipe, Session};
use dashmap::{DashMap, DashSet};
use defer::defer;
use futures::{
    lock::{Mutex, MutexGuard},
    task::{self, AtomicWaker},
    FutureExt, Stream, TryStream,
};
use ssh_packet::{connect, Packet};

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
        interest: Interest,
    ) -> task::Poll<Option<assh::Result<Packet>>> {
        tracing::trace!("POLLED ({interest:?})");
        // This is a genuine programming error from us if this happens,
        // which makes sense to panic!() to ensure test failure.
        #[allow(clippy::panic)]
        if let Some(waker) = self.interests.get(&interest) {
            waker.register(cx.waker());
        } else {
            panic!("Unable to register Waker to the `{interest:?}` interest, interest is not yet declared");
        }

        let mut buffer = futures::ready!(self.poll_recv(cx))?;

        tracing::trace!("RDY ({interest:?})");

        match buffer.take() {
            None => {
                self.interests.remove(&interest);
                for waker in self.interests.iter() {
                    waker.wake();
                }
                self.interests.clear();

                tracing::trace!("DEAD ({interest:?})");

                task::Poll::Ready(None)
            }
            Some(packet) => {
                let packet_interest = Interest::from(&packet);

                if interest == packet_interest {
                    tracing::trace!("HIT ({interest:?})");

                    task::Poll::Ready(Some(Ok(packet)))
                } else {
                    match (&packet_interest, self.interests.get(&packet_interest)) {
                        (packet_interest, Some(waker)) => {
                            tracing::trace!("MISS ({interest:?}), WOKE {packet_interest:?}");

                            *buffer = Some(packet);

                            waker.wake();
                            task::Poll::Pending
                        }
                        _ => {
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
        // This is a genuine programming error from the user of the crate,
        // and could cause all sorts of runtime inconsistencies.
        #[allow(clippy::panic)]
        if self.interests.remove(interest).is_none() {
            panic!("Interest `({interest:?})` wasn't already registered");
        }

        tracing::trace!("Unregistered interest for `{interest:?}`");
    }

    // fn local_id(&self) -> u32 {
    //     self.channels
    //         .keys()
    //         .max()
    //         .map(|x| x + 1)
    //         .unwrap_or_default()
    // }

    // /// Make a _global request_ with the provided `context`.
    // pub async fn global_request(
    //     &self,
    //     context: GlobalRequestContext,
    // ) -> Result<global_request::GlobalRequest> {
    //     let with_port = matches!(context, GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

    //     self.session
    //         .lock()
    //         .await
    //         .send(&connect::GlobalRequest {
    //             want_reply: true.into(),
    //             context,
    //         })
    //         .await?;

    //     let packet = self.recv().await?;
    //     if let Ok(connect::RequestFailure) = packet.to() {
    //         Ok(global_request::GlobalRequest::Rejected)
    //     } else if with_port {
    //         if let Ok(connect::ForwardingSuccess { bound_port }) = packet.to() {
    //             Ok(global_request::GlobalRequest::AcceptedPort(bound_port))
    //         } else {
    //             Err(assh::Error::UnexpectedMessage.into())
    //         }
    //     } else if let Ok(connect::RequestSuccess) = packet.to() {
    //         Ok(global_request::GlobalRequest::Accepted)
    //     } else {
    //         Err(assh::Error::UnexpectedMessage.into())
    //     }
    // }

    /// Iterate over the incoming _global requests_ from the peer.
    pub fn global_requests(
        &self,
    ) -> impl TryStream<Ok = global_request::GlobalRequest<'_, IO, S>, Error = crate::Error> + '_
    {
        const INTEREST: Interest = Interest::GlobalRequest;

        self.register(INTEREST);
        let unregister_on_drop = defer::defer(|| self.unregister(&INTEREST));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;

            self.poll_take(cx, INTEREST)
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
        const INTEREST: Interest = Interest::ChannelOpen;

        self.register(INTEREST);
        let unregister_on_drop = defer::defer(|| self.unregister(&INTEREST));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;

            self.poll_take(cx, INTEREST)
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
