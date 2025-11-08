//! Multiplexed I/O and requests on _channels_.

use std::{num::NonZeroU32, task};

use assh::{Pipe, side::Side};
use dashmap::DashMap;
use futures::{AsyncRead, AsyncWrite, FutureExt, TryStream};
use ssh_packet::{binrw, connect};

use crate::{
    Error, Result,
    mux::{Interest, Mux},
};

mod io;

mod id;
pub(crate) use id::Id;

mod window;
pub(crate) use window::{LocalWindow, RemoteWindow};

pub mod request;

/// A reference to an opened _channel_.
pub struct Channel<'s, IO: Pipe, S: Side> {
    mux: &'s Mux<IO, S>,

    id: Id,

    local_window: LocalWindow,
    remote_window: RemoteWindow,
    remote_maxpack: u32,

    streams: DashMap<Option<NonZeroU32>, flume::Sender<Vec<u8>>>,
}

impl<'s, IO, S> Channel<'s, IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub(crate) fn new(
        mux: &'s Mux<IO, S>,
        id: Id,
        remote_window: u32,
        remote_maxpack: u32,
    ) -> Self {
        mux.register(Interest::ChannelClose(id.local()));
        mux.register(Interest::ChannelData(id.local()));
        mux.register(Interest::ChannelEof(id.local()));
        mux.register(Interest::ChannelWindowAdjust(id.local()));

        Self {
            mux,

            id,

            local_window: Default::default(),
            remote_window: RemoteWindow::from(remote_window),
            remote_maxpack,

            streams: Default::default(),
        }
    }

    fn unregister_all(&self) {
        self.mux.unregister_if(
            |interest| matches!(interest, Interest::ChannelRequest(id) | Interest::ChannelResponse(id) if id == &self.id.local()),
        );

        self.streams.clear();

        self.mux
            .unregister(&Interest::ChannelWindowAdjust(self.id.local()));
        self.mux.unregister(&Interest::ChannelEof(self.id.local()));
        self.mux.unregister(&Interest::ChannelData(self.id.local()));
        self.mux
            .unregister(&Interest::ChannelClose(self.id.local()));
    }

    fn poll(&self, cx: &mut task::Context) -> task::Poll<assh::Result<()>> {
        if let task::Poll::Ready(Some(result)) = self
            .mux
            .poll_interest::<()>(cx, &Interest::ChannelClose(self.id.local()))
        {
            result?;

            self.unregister_all();

            tracing::debug!(
                "Peer closed channel #{}, unregistered all streams and interests",
                self.id.local()
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else if let task::Poll::Ready(Some(result)) = self
            .mux
            .poll_interest(cx, &Interest::ChannelData(self.id.local()))
        {
            #[binrw::binrw]
            #[br(little)]
            enum Data {
                Plain(connect::ChannelData<'static>),
                Extended(connect::ChannelExtendedData<'static>),
            }

            let (stream_id, data) = match result? {
                Data::Plain(message) => (None, message.data.into_vec()),
                Data::Extended(message) => (Some(message.data_type), message.data.into_vec()),
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
            .mux
            .poll_interest::<()>(cx, &Interest::ChannelEof(self.id.local()))
        {
            result?;

            self.streams.clear();

            tracing::debug!(
                "Peer sent an EOF for channel #{}, unregistered all streams",
                self.id.local()
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else if let task::Poll::Ready(Some(result)) =
            self.mux.poll_interest::<connect::ChannelWindowAdjust>(
                cx,
                &Interest::ChannelWindowAdjust(self.id.local()),
            )
        {
            let bytes_to_add = result?.bytes_to_add;
            self.remote_window.replenish(bytes_to_add);

            tracing::debug!(
                "Peer extended data window by `{}` bytes for channel #{}",
                bytes_to_add,
                self.id.local()
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else {
            task::Poll::Ready(Ok(()))
        }
    }

    fn poll_interest<T>(
        &self,
        cx: &mut task::Context,
        interest: &Interest,
    ) -> task::Poll<Option<assh::Result<T>>>
    where
        T: for<'args> binrw::BinRead<Args<'args> = ()> + binrw::meta::ReadEndian,
    {
        futures::ready!(self.poll(cx))?;

        self.mux.poll_interest(cx, interest)
    }

    /// Iterate over the incoming _channel requests_.
    pub fn requests(&self) -> impl TryStream<Ok = request::Request<'_, IO, S>, Error = Error> + '_ {
        let interest = Interest::ChannelRequest(self.id.local());
        let unregister_on_drop = self.mux.register_scoped(interest);

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span =
                tracing::debug_span!("Channel::request", channel = self.id.local()).entered();

            self.poll_interest(cx, &interest)
                .map_ok(|inner| request::Request::new(self, inner))
                .map_err(Into::into)
        })
    }

    // TODO: (ux) Compact `Self::request`, `Self::request_wait` with a trait ?

    /// Send a _channel request_.
    pub async fn request(&self, context: connect::ChannelRequestContext<'_>) -> Result<()> {
        self.mux
            .send(&connect::ChannelRequest {
                recipient_channel: self.id.remote(),
                want_reply: false.into(),
                context,
            })
            .await?;

        Ok(())
    }

    /// Send a _channel request_, and wait for it's response.
    pub async fn request_wait(
        &self,
        context: connect::ChannelRequestContext<'_>,
    ) -> Result<request::Response> {
        let interest = Interest::ChannelResponse(self.id.local());
        let _unregister_on_drop = self.mux.register_scoped(interest);

        self.mux
            .send(&connect::ChannelRequest {
                recipient_channel: self.id.remote(),
                want_reply: true.into(),
                context,
            })
            .await?;

        #[binrw::binrw]
        #[br(little)]
        enum Response {
            Success(connect::ChannelSuccess),
            Failure(connect::ChannelFailure),
        }

        futures::future::poll_fn(|cx| self.mux.poll_interest(cx, &interest))
            .map(|polled| match polled.transpose()? {
                Some(Response::Success(_)) => Ok(request::Response::Success),
                Some(Response::Failure(_)) => Ok(request::Response::Failure),
                _ => Err(Error::ChannelClosed),
            })
            .await
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
        self.mux
            .send(&connect::ChannelEof {
                recipient_channel: self.id.remote(),
            })
            .await
            .map_err(|_| Error::ChannelClosed)
    }
}

impl<'s, IO: Pipe, S: Side> Drop for Channel<'s, IO, S> {
    fn drop(&mut self) {
        self.unregister_all();

        tracing::debug!("Reporting channel #{} as closed", self.id.local());

        self.mux.feed(&connect::ChannelClose {
            recipient_channel: self.id.remote(),
        });
    }
}
