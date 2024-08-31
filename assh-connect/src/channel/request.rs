//! The _channel requests_ and responses.

use assh::{side::Side, Pipe};
use ssh_packet::connect;

use super::Channel;
use crate::{mux::Mux, Result};

#[doc(no_inline)]
pub use connect::ChannelRequestContext;

/// A response to a _channel request_.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The request succeeded.
    Success,

    /// The request failed.
    Failure,
}

/// A received _channel request_.
pub struct Request<'s, IO: Pipe, S: Side> {
    channel: &'s Channel<'s, IO, S>,
    inner: Option<connect::ChannelRequest>,
}

impl<'s, IO: Pipe, S: Side> Request<'s, IO, S> {
    pub(super) fn new(channel: &'s Channel<'s, IO, S>, inner: connect::ChannelRequest) -> Self {
        Self {
            channel,
            inner: Some(inner),
        }
    }

    /// Accept the channel request.
    pub async fn accept(mut self) -> Result<()> {
        let inner = self
            .inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        if *inner.want_reply {
            self.channel
                .mux
                .send(&connect::ChannelSuccess {
                    recipient_channel: self.channel.id.remote(),
                })
                .await?;
        }

        Ok(())
    }

    pub(crate) fn rejected(mux: &Mux<IO, S>, recipient_channel: u32) {
        mux.feed(&connect::ChannelFailure { recipient_channel });
    }

    /// Reject the channel request.
    pub async fn reject(mut self) -> Result<()> {
        let inner = self
            .inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        if *inner.want_reply {
            Self::rejected(self.channel.mux, self.channel.id.remote());
            self.channel.mux.flush().await?;
        }

        Ok(())
    }

    /// Access the _context_ of the channel request.
    pub fn cx(&self) -> &connect::ChannelRequestContext {
        &self
            .inner
            .as_ref()
            .expect("Inner value has been dropped before the outer structure")
            .context
    }
}

impl<'s, IO: Pipe, S: Side> Drop for Request<'s, IO, S> {
    fn drop(&mut self) {
        if matches!(&self.inner, Some(inner) if *inner.want_reply) {
            Self::rejected(self.channel.mux, self.channel.id.remote());
        }
    }
}
