//! The _channel requests_ and responses.

use assh::{side::Side, Pipe};
use ssh_packet::connect;

use super::Channel;
use crate::Result;

#[doc(no_inline)]
pub use connect::ChannelRequestContext;

// TODO: (compliance) Drop implementation ?

/// A response to a _channel request_.
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
                .mux
                .send(&connect::ChannelSuccess {
                    recipient_channel: self.channel.remote_id,
                })
                .await?;
        }

        Ok(())
    }

    /// Reject the channel request.
    pub async fn reject(self) -> Result<()> {
        if *self.inner.want_reply {
            self.channel
                .mux
                .send(&connect::ChannelFailure {
                    recipient_channel: self.channel.remote_id,
                })
                .await?;
        }

        Ok(())
    }
}
