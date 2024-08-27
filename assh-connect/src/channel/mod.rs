//! Multiplexed I/O and requests on _channels_.

use core::task;
use std::num::NonZeroU32;

use assh::{side::Side, Pipe};
use dashmap::DashMap;
use futures::{AsyncRead, AsyncWrite, SinkExt, TryStream};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{connect::Connect, interest::Interest, Error, Result};

mod io;

mod window;
pub(super) use window::{LocalWindow, RemoteWindow};

pub mod request;

/// A reference to an opened _channel_.
pub struct Channel<'a, IO: Pipe, S: Side> {
    connect: &'a Connect<IO, S>,

    local_id: u32,
    local_window: LocalWindow,

    remote_id: u32,
    remote_window: RemoteWindow,
    remote_maxpack: u32,

    streams: DashMap<Option<NonZeroU32>, flume::Sender<Vec<u8>>>,
}

impl<'a, IO: Pipe, S: Side> Channel<'a, IO, S> {
    pub(crate) fn new(
        connect: &'a Connect<IO, S>,
        local_id: u32,
        remote_id: u32,
        remote_window: u32,
        remote_maxpack: u32,
    ) -> Self {
        connect.register(Interest::ChannelClose(local_id));
        connect.register(Interest::ChannelData(local_id));
        connect.register(Interest::ChannelEof(local_id));
        connect.register(Interest::ChannelWindowAdjust(local_id));

        Self {
            connect,

            local_id,
            local_window: Default::default(),

            remote_id,
            remote_window: RemoteWindow::from(remote_window),
            remote_maxpack,

            streams: Default::default(),
        }
    }

    fn unregister_all(&self) {
        self.connect.unregister_if(
            |interest| matches!(interest, Interest::ChannelRequest(id) | Interest::ChannelResponse(id) if id == &self.local_id),
        );

        self.streams.clear();

        self.connect
            .unregister(&Interest::ChannelWindowAdjust(self.local_id));
        self.connect
            .unregister(&Interest::ChannelEof(self.local_id));
        self.connect
            .unregister(&Interest::ChannelData(self.local_id));
        self.connect
            .unregister(&Interest::ChannelClose(self.local_id));
    }

    fn poll_for(
        &self,
        cx: &mut task::Context,
        interest: &Interest,
    ) -> task::Poll<Option<assh::Result<Packet>>> {
        if let task::Poll::Ready(Some(result)) = self
            .connect
            .poll_for(cx, &Interest::ChannelClose(self.local_id))
        {
            result?;

            self.unregister_all();

            tracing::debug!(
                "Peer closed channel #{}, unregistered all streams and interests",
                self.local_id
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else if let task::Poll::Ready(Some(result)) = self
            .connect
            .poll_for(cx, &Interest::ChannelData(self.local_id))
        {
            let packet = result?;

            let (stream_id, data) = if let Ok(message) = packet.to::<connect::ChannelData>() {
                (None, message.data.into_vec())
            } else if let Ok(message) = packet.to::<connect::ChannelExtendedData>() {
                (Some(message.data_type), message.data.into_vec())
            } else {
                unreachable!()
            };

            match self.streams.get(&stream_id) {
                Some(sender) => {
                    sender.send(data).ok();
                }
                None => {
                    tracing::debug!("Received an unhandled stream message for {:?}", stream_id);
                }
            }

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else if let task::Poll::Ready(Some(result)) = self
            .connect
            .poll_for(cx, &Interest::ChannelEof(self.local_id))
        {
            result?;

            self.streams.clear();

            tracing::debug!(
                "Peer sent an EOF for channel #{}, unregistered all streams",
                self.local_id
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else if let task::Poll::Ready(Some(result)) = self
            .connect
            .poll_for(cx, &Interest::ChannelWindowAdjust(self.local_id))
        {
            let bytes_to_add = result?.to::<connect::ChannelWindowAdjust>()?.bytes_to_add;
            self.remote_window.replenish(bytes_to_add);

            tracing::debug!(
                "Peer extended data window by `{}` bytes for channel #{}",
                bytes_to_add,
                self.local_id
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else {
            self.connect.poll_for(cx, interest)
        }
    }

    /// Iterate over the incoming _channel requests_.
    pub fn requests(&self) -> impl TryStream<Ok = request::Request<'_, IO, S>, Error = Error> + '_ {
        let interest = Interest::ChannelRequest(self.local_id);

        self.connect.register(interest);
        let unregister_on_drop = defer::defer(move || self.connect.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Channel::request", channel = self.local_id).entered();

            self.poll_for(cx, &interest)
                .map_ok(|packet| request::Request::new(self, packet.to().unwrap()))
                .map_err(Into::into)
        })
    }

    // TODO: Compact `Self::request`, `Self::request_wait` with a trait ?

    /// Send a _channel request_.
    pub async fn request(&self, context: connect::ChannelRequestContext) -> Result<()> {
        self.connect
            .send(
                connect::ChannelRequest {
                    recipient_channel: self.remote_id,
                    want_reply: false.into(),
                    context,
                }
                .into_packet(),
            )
            .await?;

        Ok(())
    }

    /// Send a _channel request_, and wait for it's response.
    pub async fn request_wait(
        &self,
        context: connect::ChannelRequestContext,
    ) -> Result<request::Response> {
        let interest = Interest::ChannelResponse(self.local_id);
        self.connect.register(interest);

        self.connect
            .send(
                connect::ChannelRequest {
                    recipient_channel: self.remote_id,
                    want_reply: true.into(),
                    context,
                }
                .into_packet(),
            )
            .await?;

        let response = futures::future::poll_fn(|cx| {
            let response =
                futures::ready!(self.poll_for(cx, &interest)).and_then(|packet| match packet {
                    Ok(packet) => {
                        if packet.to::<connect::ChannelSuccess>().is_ok() {
                            Some(Ok(request::Response::Success))
                        } else if packet.to::<connect::ChannelFailure>().is_ok() {
                            Some(Ok(request::Response::Failure))
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

        self.connect.unregister(&interest);

        Ok(response??)
    }

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

    /// Make a writer for current channel's _data_ stream.
    ///
    /// ## Note:
    /// The writer does not flush on [`Drop`], the caller is responsible to call
    /// [`futures::AsyncWriteExt::flush`] before dropping.
    #[must_use]
    pub fn as_writer(&self) -> impl AsyncWrite + '_ {
        io::Write::new(self, None)
    }

    /// Make a writer for current channel's _extended data_ stream.
    ///
    /// ## Note:
    /// The writer does not flush on [`Drop`], the caller is responsible to call
    /// [`futures::AsyncWriteExt::flush`] before dropping.
    #[must_use]
    pub fn as_writer_ext(&self, ext: NonZeroU32) -> impl AsyncWrite + '_ {
        io::Write::new(self, Some(ext))
    }

    /// Signal to the peer we won't send any more data in the current channel.
    pub async fn eof(&self) -> Result<()> {
        self.connect
            .send(
                connect::ChannelEof {
                    recipient_channel: self.remote_id,
                }
                .into_packet(),
            )
            .await
            .map_err(|_| Error::ChannelClosed)
    }
}

impl<'a, IO: Pipe, S: Side> Drop for Channel<'a, IO, S> {
    fn drop(&mut self) {
        self.unregister_all();

        tracing::debug!("Reporting channel #{} as closed", self.local_id);

        // TODO: Find a better way than this "bad bad loop™"
        loop {
            if let Some(mut poller) = self.connect.poller.try_lock() {
                poller
                    .start_send_unpin(
                        connect::ChannelClose {
                            recipient_channel: self.remote_id,
                        }
                        .into_packet(),
                    )
                    .ok();

                break;
            }
        }
    }
}
