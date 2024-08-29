//! Multiplexed I/O and requests on _channels_.

use std::{num::NonZeroU32, task};

use assh::{side::Side, Pipe};
use dashmap::DashMap;
use futures::{AsyncRead, AsyncWrite, TryStream};
use ssh_packet::{binrw, connect};

use crate::{
    mux::{Interest, Mux},
    Error, Result,
};

mod io;

mod window;
pub(super) use window::{LocalWindow, RemoteWindow};

pub mod request;

/// A reference to an opened _channel_.
pub struct Channel<'a, IO: Pipe, S: Side> {
    mux: &'a Mux<IO, S>,

    local_id: u32,
    local_window: LocalWindow,

    remote_id: u32,
    remote_window: RemoteWindow,
    remote_maxpack: u32,

    streams: DashMap<Option<NonZeroU32>, flume::Sender<Vec<u8>>>,
}

impl<'a, IO: Pipe, S: Side> Channel<'a, IO, S> {
    pub(crate) fn new(
        mux: &'a Mux<IO, S>,
        local_id: u32,
        remote_id: u32,
        remote_window: u32,
        remote_maxpack: u32,
    ) -> Self {
        mux.register(Interest::ChannelClose(local_id));
        mux.register(Interest::ChannelData(local_id));
        mux.register(Interest::ChannelEof(local_id));
        mux.register(Interest::ChannelWindowAdjust(local_id));

        Self {
            mux,

            local_id,
            local_window: Default::default(),

            remote_id,
            remote_window: RemoteWindow::from(remote_window),
            remote_maxpack,

            streams: Default::default(),
        }
    }

    fn unregister_all(&self) {
        self.mux.unregister_if(
            |interest| matches!(interest, Interest::ChannelRequest(id) | Interest::ChannelResponse(id) if id == &self.local_id),
        );

        self.streams.clear();

        self.mux
            .unregister(&Interest::ChannelWindowAdjust(self.local_id));
        self.mux.unregister(&Interest::ChannelEof(self.local_id));
        self.mux.unregister(&Interest::ChannelData(self.local_id));
        self.mux.unregister(&Interest::ChannelClose(self.local_id));
    }

    fn poll(&self, cx: &mut task::Context) -> task::Poll<assh::Result<()>> {
        if let task::Poll::Ready(Some(result)) = self
            .mux
            .poll_interest(cx, &Interest::ChannelClose(self.local_id))
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
            .mux
            .poll_interest(cx, &Interest::ChannelData(self.local_id))
        {
            #[binrw::binrw]
            #[br(little)]
            enum Data {
                Plain(connect::ChannelData),
                Extended(connect::ChannelExtendedData),
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
            .poll_interest(cx, &Interest::ChannelEof(self.local_id))
        {
            result?;

            self.streams.clear();

            tracing::debug!(
                "Peer sent an EOF for channel #{}, unregistered all streams",
                self.local_id
            );

            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else if let task::Poll::Ready(Some(result)) =
            self.mux.poll_interest::<connect::ChannelWindowAdjust>(
                cx,
                &Interest::ChannelWindowAdjust(self.local_id),
            )
        {
            let bytes_to_add = result?.bytes_to_add;
            self.remote_window.replenish(bytes_to_add);

            tracing::debug!(
                "Peer extended data window by `{}` bytes for channel #{}",
                bytes_to_add,
                self.local_id
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
        let interest = Interest::ChannelRequest(self.local_id);

        self.mux.register(interest);
        let unregister_on_drop = defer::defer(move || self.mux.unregister(&interest));

        futures::stream::poll_fn(move |cx| {
            let _moved = &unregister_on_drop;
            let _span = tracing::debug_span!("Channel::request", channel = self.local_id).entered();

            self.poll_interest(cx, &interest)
                .map_ok(|message| request::Request::new(self, message))
                .map_err(Into::into)
        })
    }

    // TODO: Compact `Self::request`, `Self::request_wait` with a trait ?

    /// Send a _channel request_.
    pub async fn request(&self, context: connect::ChannelRequestContext) -> Result<()> {
        self.mux
            .send(&connect::ChannelRequest {
                recipient_channel: self.remote_id,
                want_reply: false.into(),
                context,
            })
            .await?;

        Ok(())
    }

    /// Send a _channel request_, and wait for it's response.
    pub async fn request_wait(
        &self,
        context: connect::ChannelRequestContext,
    ) -> Result<request::Response> {
        let interest = Interest::ChannelResponse(self.local_id);
        self.mux.register(interest);

        self.mux
            .send(&connect::ChannelRequest {
                recipient_channel: self.remote_id,
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

        let result = futures::future::poll_fn(|cx| {
            let polled = futures::ready!(self.mux.poll_interest(cx, &interest)).transpose()?;

            task::Poll::Ready(match polled {
                Some(Response::Success(_)) => {
                    let response = request::Response::Success;

                    Some(Ok::<_, assh::Error>(response))
                }

                Some(Response::Failure(_)) => {
                    let response = request::Response::Failure;

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
                recipient_channel: self.remote_id,
            })
            .await
            .map_err(|_| Error::ChannelClosed)
    }
}

impl<'a, IO: Pipe, S: Side> Drop for Channel<'a, IO, S> {
    fn drop(&mut self) {
        self.unregister_all();

        tracing::debug!("Reporting channel #{} as closed", self.local_id);

        self.mux.feed(&connect::ChannelClose {
            recipient_channel: self.remote_id,
        });
    }
}
