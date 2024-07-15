//! Definition of the [`Channel`] struct that provides isolated I/O on SSH channels.

use std::{num::NonZeroU32, sync::atomic::AtomicBool};

use assh::{side::Side, Pipe};
use futures::{AsyncRead, TryStream};
use ssh_packet::connect;

use crate::connect::{Connect, Interest};

#[doc(no_inline)]
pub use connect::ChannelRequestContext;

mod io;

mod window;
pub(super) use window::{LocalWindow, RemoteWindow};

mod request;
pub use request::{Request, Response};

/// A reference to an opened channel in the session.
pub struct Channel<'r, IO: Pipe, S: Side> {
    connect: &'r Connect<IO, S>,
    eof: AtomicBool,

    local_id: u32,
    local_window: LocalWindow,

    remote_id: u32,
    remote_window: RemoteWindow,
    remote_maxpack: u32,
}

impl<'r, IO: Pipe, S: Side> Channel<'r, IO, S> {
    pub(crate) fn from_request(
        connect: &'r Connect<IO, S>,
        local_id: u32,
        request: connect::ChannelOpen,
    ) -> Self {
        Self {
            connect,
            eof: Default::default(),

            local_id,
            local_window: LocalWindow::default(),

            remote_id: request.sender_channel,
            remote_window: RemoteWindow::from(request.initial_window_size),
            remote_maxpack: request.maximum_packet_size,
        }
    }

    pub(crate) fn from_confirmation(
        connect: &'r Connect<IO, S>,
        local_id: u32,
        confirmation: connect::ChannelOpenConfirmation,
    ) -> Self {
        Self {
            connect,
            eof: Default::default(),

            local_id,
            local_window: LocalWindow::default(),

            remote_id: confirmation.sender_channel,
            remote_window: RemoteWindow::from(confirmation.initial_window_size),
            remote_maxpack: confirmation.maximum_packet_size,
        }
    }

    /// Iterate over the incoming _channel requests_ on the channel.
    pub fn requests(
        &self,
    ) -> impl TryStream<Ok = request::Request<'_, IO, S>, Error = crate::Error> + '_ {
        let interest: Interest = Interest::ChannelRequest(self.local_id);

        self.connect.register(interest);
        let unregister_on_drop = defer::defer(move || self.connect.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;

            self.connect
                .poll_take(cx, interest)
                .map_ok(|packet| request::Request::new(self, packet.to().unwrap()))
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

    /// Make a reader for current channel's _data_ stream.
    #[must_use]
    pub fn as_reader(&self) -> impl AsyncRead + '_ {
        io::Read::new(self, None)
    }

    /// Make a reader for current channel's _extended data_ stream.
    #[must_use]
    pub fn as_reader_ext(&self, ext: NonZeroU32) -> impl AsyncRead + '_ {
        io::Read::new(self, Some(ext))
    }

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
