//! Facilities to interract with the SSH _connect_ protocol.

use std::ops::DerefMut;

use assh::{side::Side, Pipe, Session};
use futures::{lock::Mutex, stream::Peekable, StreamExt};
use ssh_packet::connect;

mod broker;
use broker::Broker;

pub(super) mod messages;

pub mod channel_open;
pub mod global_request;

#[doc(no_inline)]
pub use connect::{ChannelOpenContext, ChannelOpenFailureReason, GlobalRequestContext};

/// A wrapper around a [`Session`] to interract with the connect layer.
pub struct Connect<'s, IO, S>
where
    IO: Pipe,
    S: Side,
{
    broker: Mutex<Peekable<Broker<'s, IO, S>>>,
}

impl<'s, IO, S> Connect<'s, IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(super) fn new(session: &'s mut Session<IO, S>) -> Self {
        Self {
            broker: Mutex::new(Broker::from(session).peekable()),
        }
    }

    pub async fn packets(&self) -> impl DerefMut<Target = Peekable<Broker<'s, IO, S>>> + '_ {
        self.broker.lock().await
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

    // /// Handle global requests as they arrive from the peer.
    // pub fn on_global_requests(
    //     &self,
    // ) -> impl Stream<Item = Result<global_request::GlobalRequest>> + '_ {
    //     futures::stream::try_unfold((), |_| async move {
    //         let mut broker = self.broker.lock().await;
    //         let mut broker = std::pin::Pin::new(&mut *broker);

    //         let packet = broker
    //             .next_if(|packet| {
    //                 packet
    //                     .and_then(|packet| Ok(packet.to::<connect::GlobalRequest>()?))
    //                     .is_ok()
    //             })
    //             .await;
    //     })
    // }

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

    // /// Register the hook for _channel open requests_.
    // ///
    // /// # Note:
    // ///
    // /// Blocking the hook will block the main [`Self::spin`] loop,
    // /// which will cause new global requests and channels to stop
    // /// being processed, as well as interrupt channel I/O.
    // pub fn on_channel_open(&self) {
    //     unimplemented!()
    // }
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

        is_send::<Connect<'static, BufReader<Compat<TcpStream>>, Client>>();
        is_send::<Connect<'static, BufReader<Compat<TcpStream>>, Server>>();
    }

    #[test]
    fn assert_connect_is_sync() {
        fn is_sync<T: Sync>() {}

        is_sync::<Connect<'static, BufReader<Compat<TcpStream>>, Client>>();
        is_sync::<Connect<'static, BufReader<Compat<TcpStream>>, Server>>();
    }
}
