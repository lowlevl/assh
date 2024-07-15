use assh::{side::Side, Pipe};
use futures::SinkExt;
use ssh_packet::{
    connect::{self},
    IntoPacket,
};

use super::Channel;
use crate::Result;

// TODO: Drop implementation ?

/// A response to a channel request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The request succeeded.
    Success,

    /// The request failed.
    Failure,
}

/// A received _channel request_.
pub struct Request<'r, IO: Pipe, S: Side> {
    channel: &'r Channel<'r, IO, S>,
    inner: connect::ChannelRequest,
}

impl<'r, IO: Pipe, S: Side> Request<'r, IO, S> {
    pub(super) fn new(channel: &'r Channel<'r, IO, S>, inner: connect::ChannelRequest) -> Self {
        Self { channel, inner }
    }

    /// Access the _context_ of the channel request.
    pub fn cx(&self) -> &connect::ChannelRequestContext {
        &self.inner.context
    }

    /// Accept the channel request.
    pub async fn accept(self) -> Result<()> {
        if *self.inner.want_reply {
            self.channel
                .connect
                .poller
                .lock()
                .await
                .send(
                    connect::ChannelSuccess {
                        recipient_channel: self.channel.remote_id,
                    }
                    .into_packet(),
                )
                .await?;
        }

        Ok(())
    }

    /// Reject the channel request.
    pub async fn reject(self) -> Result<()> {
        if *self.inner.want_reply {
            self.channel
                .connect
                .poller
                .lock()
                .await
                .send(
                    connect::ChannelFailure {
                        recipient_channel: self.channel.remote_id,
                    }
                    .into_packet(),
                )
                .await?;
        }

        Ok(())
    }
}
