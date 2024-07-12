//! Definition of the [`Channel`] struct that provides isolated I/O on SSH channels.

use std::{num::NonZeroU32, sync::Arc};

use assh::{side::Side, Pipe};
use flume::{Receiver, Sender};
use futures::{AsyncRead, AsyncWrite, Stream, StreamExt, TryStream};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{
    connect::{messages, Connect},
    Error, Result,
};

#[doc(no_inline)]
pub use connect::ChannelRequestContext;

mod io;

mod mux;
pub(super) use mux::Multiplexer;

mod window;
pub(super) use window::{LocalWindow, RemoteWindow};

mod handle;
pub(super) use handle::Handle;

mod request;
pub use request::{Request, Response};

/// A reference to an opened channel in the session.
pub struct Channel<'a, IO: Pipe, S: Side> {
    connect: &'a Connect<IO, S>,
    local_id: u32,
    remote_id: u32,
}

impl<'a, IO: Pipe, S: Side> Channel<'a, IO, S> {
    pub(super) fn new(
        connect: &'a Connect<IO, S>,
        local_id: u32,
        req: connect::ChannelOpen,
    ) -> Self {
        Self {
            connect,
            local_id,
            remote_id: req.sender_channel,
        }
    }

    /// Iterate over the incoming _channel requests_ on the channel.
    pub fn requests(
        &self,
    ) -> impl TryStream<Ok = request::Request<'_, IO, S>, Error = crate::Error> + '_ {
        futures::stream::poll_fn(|cx| {
            self.connect
                .poll_take_if(cx, |request: &connect::ChannelRequest| {
                    request.recipient_channel == self.local_id
                })
                .map_ok(|request| request::Request::new(self, request))
                .map_err(Into::into)
        })
    }

    // /// Send a request in the current channel.
    // pub async fn request(&self, context: ChannelRequestContext) -> Result<Response> {
    //     self.outgoing
    //         .send_async(
    //             connect::ChannelRequest {
    //                 recipient_channel: self.remote_id,
    //                 want_reply: true.into(),
    //                 context,
    //             }
    //             .into_packet(),
    //         )
    //         .await
    //         .map_err(|_| Error::ChannelClosed)?;

    //     match self.incoming.recv_async().await {
    //         Ok(messages::Control::Success(_)) => Ok(Response::Success),
    //         Ok(messages::Control::Failure(_)) => Ok(Response::Failure),
    //         Ok(_) => Err(assh::Error::UnexpectedMessage.into()),
    //         Err(_) => Err(Error::ChannelClosed),
    //     }
    // }

    // /// Make a reader for current channel's _data_ stream.
    // #[must_use]
    // pub fn as_reader(&self) -> impl AsyncRead + '_ {
    //     io::Read::new(self.remote_id, None, &self.mux, self.outgoing.sink())
    // }

    // /// Make a reader for current channel's _extended data_ stream.
    // #[must_use]
    // pub fn as_reader_ext(&self, ext: NonZeroU32) -> impl AsyncRead + '_ {
    //     io::Read::new(self.remote_id, Some(ext), &self.mux, self.outgoing.sink())
    // }

    // /// Make a writer for current channel's _data_ stream.
    // ///
    // /// ## Note:
    // /// The writer does not flush [`Drop`], the caller is responsible to call
    // /// [`futures::AsyncWriteExt::flush`] before dropping.
    // #[must_use]
    // pub fn as_writer(&self) -> impl AsyncWrite + '_ {
    //     io::Write::new(
    //         self.remote_id,
    //         None,
    //         self.outgoing.sink(),
    //         &self.window,
    //         self.remote_maximum_packet_size,
    //     )
    // }

    // /// Make a writer for current channel's _extended data_ stream.
    // ///
    // /// ## Note:
    // /// The writer does not flush [`Drop`], the caller is responsible to call
    // /// [`futures::AsyncWriteExt::flush`] before dropping.
    // #[must_use]
    // pub fn as_writer_ext(&self, ext: NonZeroU32) -> impl AsyncWrite + '_ {
    //     io::Write::new(
    //         self.remote_id,
    //         Some(ext),
    //         self.outgoing.sink(),
    //         &self.window,
    //         self.remote_maximum_packet_size,
    //     )
    // }

    // /// Signal to the peer we won't send any more data in the current channel.
    // pub async fn eof(&self) -> Result<()> {
    //     self.outgoing
    //         .send_async(
    //             connect::ChannelEof {
    //                 recipient_channel: self.remote_id,
    //             }
    //             .into_packet(),
    //         )
    //         .await
    //         .map_err(|_| Error::ChannelClosed)
    // }

    // /// Tells whether the channel has been closed.
    // pub async fn is_closed(&self) -> bool {
    //     self.incoming.is_disconnected()
    // }
}

impl<'a, IO: Pipe, S: Side> Drop for Channel<'a, IO, S> {
    fn drop(&mut self) {
        // tracing::debug!("Reporting channel closed %{}", self.remote_id);

        self.connect.channels.remove(&self.local_id);

        // self.outgoing
        //     .try_send(
        //         connect::ChannelClose {
        //             recipient_channel: self.remote_id,
        //         }
        //         .into_packet(),
        //     )
        //     .ok();
    }
}
