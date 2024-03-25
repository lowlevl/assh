//! Facilities to interract with SSH channels.

use std::sync::atomic::AtomicU32;

use assh::Result;
use futures::{AsyncRead, AsyncWrite};
use ssh_packet::connect;

mod msg;
pub use msg::Msg;

mod stream;

/// A response to a channel request.
#[derive(Debug)]
pub enum Response {
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

    rx: flume::Receiver<Msg>,
    tx: flume::Sender<Msg>,
}

impl Channel {
    /// Interface with the current channel to transfer binary data.
    pub fn as_data(&self) -> impl AsyncRead + AsyncWrite + '_ {
        self.as_data_ext(None)
    }

    /// Interface with the current channel to transfer binary data,
    /// either as [`connect::ChannelData`] or [`connect::ChannelExtendedData`].
    pub fn as_data_ext(
        &self,
        ext: Option<connect::ChannelExtendedDataType>,
    ) -> impl AsyncRead + AsyncWrite + '_ {
        stream::Stream { channel: self, ext }
    }

    /// Send a request on the current channel.
    pub async fn request(&self, context: connect::ChannelRequestContext) -> Result<Response> {
        self.tx
            .send_async(Msg::ChannelRequest(connect::ChannelRequest {
                recipient_channel: self.identifier,
                want_reply: true.into(),
                context,
            }))
            .await?;

        match self.rx.recv_async().await? {
            Msg::ChannelSuccess(_) => Ok(Response::Success),
            Msg::ChannelFailure(_) => Ok(Response::Failure),
            _ => Err(todo!("Unhandled packet")),
        }
    }

    /// Receive and handle a request on the current channel.
    pub async fn on_request(
        &self,
        handler: impl FnMut(connect::ChannelRequestContext) -> Response,
    ) -> Result<()> {
        match self.rx.recv_async().await? {
            Msg::ChannelRequest(request) => {
                let response = handler(request.context);

                if request.want_reply {
                    match response {
                        Response::Success => {
                            self.tx
                                .send_async(Msg::ChannelSuccess(connect::ChannelSuccess {
                                    recipient_channel: self.identifier,
                                }))
                                .await?;
                        }
                        Response::Failure => {
                            self.tx
                                .send_async(Msg::ChannelFailure(connect::ChannelFailure {
                                    recipient_channel: self.identifier,
                                }))
                                .await?;
                        }
                    }
                }

                Ok(())
            }
            _ => Err(todo!("Unhandled packet")),
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.tx
            .send(Msg::ChannelClose(connect::ChannelClose {
                recipient_channel: self.identifier,
            }))
            .inspect_err(|err| {
                tracing::error!(
                    "Unable to send the closing message for channel #{}: {err}",
                    self.identifier
                )
            });
    }
}
