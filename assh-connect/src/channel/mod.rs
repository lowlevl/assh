//! Facilities to interract with SSH channels.

use std::sync::atomic::AtomicU32;

use futures::{AsyncRead, AsyncWrite};
use ssh_packet::connect;

use crate::{Error, Result};

mod io;

mod msg;
pub(super) use msg::Msg;

/// A response to a channel request.
#[derive(Debug)]
pub enum RequestResponse {
    /// The request succeeded.
    Success,

    /// The request failed.
    Failure,
}

/// A reference to an opened channel in the session.
#[derive(Debug)]
pub struct Channel {
    identifier: u32,

    window_size: AtomicU32,
    maximum_packet_size: u32,

    sender: flume::Sender<Msg>,
    receiver: flume::Receiver<Msg>,
}

impl Channel {
    pub(super) fn new(
        identifier: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
        sender: flume::Sender<Msg>,
    ) -> (Self, flume::Sender<Msg>) {
        let (tx, rx) = flume::unbounded();

        (
            Self {
                identifier,
                window_size: initial_window_size.into(),
                maximum_packet_size,
                receiver: rx,
                sender,
            },
            tx,
        )
    }

    /// Make a reader for current channel's _data_ stream.
    ///
    /// # Caveats
    ///
    /// Even though the interface allows having multiple _readers_,
    /// polling for a reader will discard other data types
    /// and polling concurrently for more than one reader may cause data integrity issues.
    pub fn as_reader(&self) -> impl AsyncRead + '_ {
        io::Read::new(self, None)
    }

    /// Make a reader for current channel's _extended data_ stream.
    ///
    /// # Caveats
    ///
    /// Even though the interface allows having multiple _readers_,
    /// polling for a reader will discard other data types
    /// and polling concurrently for more than one reader may cause data integrity issues.
    pub fn as_reader_ext(&self, ext: connect::ChannelExtendedDataType) -> impl AsyncRead + '_ {
        io::Read::new(self, Some(ext))
    }

    /// Make a writer for current channel's _data_ stream.
    pub fn as_writer(&self) -> impl AsyncWrite + '_ {
        io::Write::new(self, None)
    }

    /// Make a writer for current channel's _extended data_ stream.
    pub fn as_writer_ext(&self, ext: connect::ChannelExtendedDataType) -> impl AsyncWrite + '_ {
        io::Write::new(self, Some(ext))
    }

    /// Send a request on the current channel.
    pub async fn request(
        &self,
        context: connect::ChannelRequestContext,
    ) -> Result<RequestResponse> {
        self.sender
            .send_async(Msg::Request(connect::ChannelRequest {
                recipient_channel: self.identifier,
                want_reply: true.into(),
                context,
            }))
            .await
            .map_err(|_| Error::ChannelClosed)?;

        match self
            .receiver
            .recv_async()
            .await
            .map_err(|_| Error::ChannelClosed)?
        {
            Msg::Success(_) => Ok(RequestResponse::Success),
            Msg::Failure(_) => Ok(RequestResponse::Failure),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Receive and handle a request on the current channel.
    pub async fn on_request(
        &self,
        mut handler: impl FnMut(connect::ChannelRequestContext) -> RequestResponse,
    ) -> Result<()> {
        match self
            .receiver
            .recv_async()
            .await
            .map_err(|_| Error::ChannelClosed)?
        {
            Msg::Request(request) => {
                let response = handler(request.context);

                if *request.want_reply {
                    match response {
                        RequestResponse::Success => {
                            self.sender
                                .send_async(Msg::Success(connect::ChannelSuccess {
                                    recipient_channel: self.identifier,
                                }))
                                .await
                                .map_err(|_| Error::ChannelClosed)?;
                        }
                        RequestResponse::Failure => {
                            self.sender
                                .send_async(Msg::Failure(connect::ChannelFailure {
                                    recipient_channel: self.identifier,
                                }))
                                .await
                                .map_err(|_| Error::ChannelClosed)?;
                        }
                    }
                }

                Ok(())
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }
}
