//! Definition of the [`Channel`] struct that provides isolated I/O on SSH channels.

use std::{num::NonZeroU32, sync::Arc};

use dashmap::DashMap;
use flume::{Receiver, Sender};
use futures::{AsyncRead, AsyncWrite, Stream, StreamExt};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{Error, Result};

#[doc(no_inline)]
pub use connect::ChannelRequestContext;

pub(super) mod io;

mod handle;
pub(super) use handle::Handle;

mod request;
pub use request::{Request, Response};

use crate::connect::messages;

pub(super) fn pair(
    remote_id: u32,
    remote_maximum_packet_size: u32,
    windows: (io::LocalWindow, io::RemoteWindow),
    outgoing: Sender<Packet>,
) -> (Channel, Handle) {
    let (control, incoming) = flume::unbounded();
    let streams = Arc::new(DashMap::new());
    let windows = (windows.0.into(), windows.1.into());

    (
        Channel {
            remote_id,
            remote_maximum_packet_size,
            incoming,
            outgoing,
            streams: streams.clone(),
            windows: windows.clone(),
        },
        Handle {
            remote_id,
            control,
            streams,
            windows,
        },
    )
}

/// A reference to an opened channel in the session.
pub struct Channel {
    remote_id: u32,
    remote_maximum_packet_size: u32,

    outgoing: Sender<Packet>,
    incoming: Receiver<messages::Control>,
    streams: Arc<DashMap<Option<NonZeroU32>, Sender<Vec<u8>>>>,
    windows: (Arc<io::LocalWindow>, Arc<io::RemoteWindow>),
}

impl Channel {
    /// Iterate over the incoming channel requests to process them.
    pub fn requests(&mut self) -> impl Stream<Item = request::Request> + Unpin + '_ {
        self.incoming.stream().filter_map(|message| {
            Box::pin(async {
                if let messages::Control::Request(request) = message {
                    Some(request::Request::new(
                        self.remote_id,
                        self.outgoing.clone(),
                        request,
                    ))
                } else {
                    None
                }
            })
        })
    }

    /// Send a request on the current channel.
    pub async fn request(&mut self, context: ChannelRequestContext) -> Result<Response> {
        self.outgoing
            .send_async(
                connect::ChannelRequest {
                    recipient_channel: self.remote_id,
                    want_reply: true.into(),
                    context,
                }
                .into_packet()
                .expect("Conversion to Packet shouldn't fail"),
            )
            .await
            .ok();

        match self.incoming.recv_async().await {
            Ok(messages::Control::Success(_)) => Ok(Response::Success),
            Ok(messages::Control::Failure(_)) => Ok(Response::Failure),
            Ok(_) => Err(assh::Error::UnexpectedMessage.into()),
            Err(_) => Err(Error::ChannelClosed),
        }
    }

    /// Make a reader for current channel's _data_ stream.
    #[must_use]
    pub fn as_reader(&self) -> impl AsyncRead {
        let (reader, sender) = io::Read::new(
            self.remote_id,
            self.outgoing.clone().into_sink(),
            self.windows.0.clone(),
        );

        self.streams.insert(None, sender);

        reader
    }

    /// Make a reader for current channel's _extended data_ stream.
    #[must_use]
    pub fn as_reader_ext(&self, ext: NonZeroU32) -> impl AsyncRead {
        let (reader, sender) = io::Read::new(
            self.remote_id,
            self.outgoing.clone().into_sink(),
            self.windows.0.clone(),
        );

        self.streams.insert(Some(ext), sender);

        reader
    }

    /// Make a writer for current channel's _data_ stream.
    ///
    /// ## Note:
    /// The writer does not flush [`Drop`], the caller is responsible to call
    /// [`futures::AsyncWriteExt::flush`] before dropping.
    #[must_use]
    pub fn as_writer(&self) -> impl AsyncWrite {
        io::Write::new(
            self.remote_id,
            None,
            self.outgoing.clone().into_sink(),
            self.windows.1.clone(),
            self.remote_maximum_packet_size,
        )
    }

    /// Make a writer for current channel's _extended data_ stream.
    ///
    /// ## Note:
    /// The writer does not flush [`Drop`], the caller is responsible to call
    /// [`futures::AsyncWriteExt::flush`] before dropping.
    #[must_use]
    pub fn as_writer_ext(&self, ext: NonZeroU32) -> impl AsyncWrite {
        io::Write::new(
            self.remote_id,
            Some(ext),
            self.outgoing.clone().into_sink(),
            self.windows.1.clone(),
            self.remote_maximum_packet_size,
        )
    }

    /// Tells whether the channel has been closed.
    pub async fn is_closed(&self) -> bool {
        self.incoming.is_disconnected()
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        tracing::debug!("Reporting channel closed %{}", self.remote_id);

        self.outgoing
            .try_send(
                connect::ChannelClose {
                    recipient_channel: self.remote_id,
                }
                .into_packet()
                .expect("Conversion to Packet shouldn't fail"),
            )
            .ok();
    }
}
