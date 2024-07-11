//! Facilities to interract with the SSH _connect_ protocol.

use std::task::Waker;

use assh::{side::Side, Pipe, Session};
use dashmap::DashMap;
use futures::{
    lock::{Mutex, MutexGuard},
    task, FutureExt, Stream, TryStream,
};
use ssh_packet::{
    binrw::{
        meta::{ReadEndian, ReadMagic},
        BinRead,
    },
    connect, Packet,
};

mod poller;
use poller::Poller;

pub(super) mod messages;

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
    poller: Mutex<Poller<IO, S>>,
    buffer: Mutex<Option<Packet>>,

    wakers: DashMap<u8, Waker>,
}

impl<IO, S> Connect<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(super) fn new(session: Session<IO, S>) -> Self {
        Self {
            poller: Mutex::new(Poller::from(session)),
            buffer: Default::default(),

            wakers: Default::default(),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut task::Context,
    ) -> task::Poll<assh::Result<MutexGuard<'_, Option<Packet>>>> {
        let mut buffer = futures::ready!(self.buffer.lock().poll_unpin(cx));

        if buffer.is_none() {
            let broker = futures::ready!(self.poller.lock().poll_unpin(cx));
            let mut broker = std::pin::Pin::new(broker);

            if let Some(res) = futures::ready!(broker.as_mut().poll_next(cx)) {
                *buffer = Some(res?);
            }
        }

        task::Poll::Ready(Ok(buffer))
    }

    fn poll_take_if<T>(
        &self,
        cx: &mut task::Context,
        mut fun: impl FnMut(&T) -> bool,
    ) -> task::Poll<Option<assh::Result<T>>>
    where
        T: for<'a> BinRead<Args<'a> = ()> + ReadEndian + ReadMagic<MagicType = u8>,
    {
        self.wakers.insert(T::MAGIC, cx.waker().clone());

        let mut buffer = futures::ready!(self.poll_recv(cx))?;
        match &*buffer {
            None => {
                self.wakers.remove(&T::MAGIC);
                for refer in self.wakers.iter() {
                    refer.value().wake_by_ref();
                }
                self.wakers.clear();

                task::Poll::Ready(None)
            }
            Some(packet) => {
                match packet.to::<T>() {
                    Ok(message) if fun(&message) => {
                        buffer.take();

                        task::Poll::Ready(Some(Ok(message)))
                    }
                    _ => {
                        if let Some((_, waker)) = self.wakers.remove(&packet.payload[0]) {
                            waker.wake();
                        }

                        // TODO: Drop unhandled messages.

                        task::Poll::Pending
                    }
                }
            }
        }
    }

    fn poll_take<T>(&self, cx: &mut task::Context) -> task::Poll<Option<assh::Result<T>>>
    where
        T: for<'a> BinRead<Args<'a> = ()> + ReadEndian + ReadMagic<MagicType = u8>,
    {
        self.poll_take_if(cx, |_| true)
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

    /// Handle _global requests_ as they arrive from the peer.
    pub fn global_requests(
        &self,
    ) -> impl TryStream<Ok = connect::GlobalRequest, Error = crate::Error> + '_ {
        futures::stream::poll_fn(|cx| self.poll_take(cx).map_err(Into::into))
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

    /// Handle _channel open requests_ as they arrive from the peer.
    pub fn channel_opens(
        &self,
    ) -> impl TryStream<Ok = connect::ChannelOpen, Error = crate::Error> + '_ {
        futures::stream::poll_fn(|cx| self.poll_take(cx).map_err(Into::into))
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
