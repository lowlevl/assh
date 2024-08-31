//! The _channel open requests_ and responses.

use assh::{side::Side, Pipe};
use ssh_packet::{arch::StringUtf8, connect};

use crate::{
    channel::{self, LocalWindow},
    mux::Mux,
    Result,
};

#[doc(no_inline)]
pub use ssh_packet::connect::{ChannelOpenContext, ChannelOpenFailureReason};

/// A response to a _channel open request_.
pub enum Response<'s, IO: Pipe, S: Side> {
    /// The request succeeded, with an opened channel.
    Success(channel::Channel<'s, IO, S>),

    /// The request failed.
    Failure {
        /// The reason for failure.
        reason: connect::ChannelOpenFailureReason,

        /// A textual description of the failure.
        description: String,
    },
}

/// A received _channel open request_.
pub struct ChannelOpen<'s, IO: Pipe, S: Side> {
    mux: &'s Mux<IO, S>,
    inner: Option<connect::ChannelOpen>,
    local_id: u32,
}

impl<'s, IO: Pipe, S: Side> ChannelOpen<'s, IO, S> {
    pub(super) fn new(mux: &'s Mux<IO, S>, inner: connect::ChannelOpen, local_id: u32) -> Self {
        Self {
            mux,
            inner: Some(inner),
            local_id,
        }
    }

    /// Accept the channel open request.
    pub async fn accept(mut self) -> Result<channel::Channel<'s, IO, S>> {
        let inner = self
            .inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        self.mux
            .send(&connect::ChannelOpenConfirmation {
                recipient_channel: inner.sender_channel,
                sender_channel: self.local_id,
                initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
            })
            .await?;

        Ok(channel::Channel::new(
            self.mux,
            self.local_id,
            inner.sender_channel,
            inner.initial_window_size,
            inner.maximum_packet_size,
        ))
    }

    pub(crate) fn rejected(
        mux: &Mux<IO, S>,
        recipient_channel: u32,
        reason: Option<connect::ChannelOpenFailureReason>,
        description: Option<StringUtf8>,
    ) {
        mux.feed(&connect::ChannelOpenFailure {
            recipient_channel,
            reason: reason.unwrap_or(connect::ChannelOpenFailureReason::AdministrativelyProhibited),
            description: description
                .map(Into::into)
                .unwrap_or_else(|| "opening channel is disallowed".into()),
            language: Default::default(),
        });
    }

    /// Reject the channel open request.
    pub async fn reject(
        mut self,
        reason: connect::ChannelOpenFailureReason,
        description: impl Into<StringUtf8>,
    ) -> Result<()> {
        let inner = self
            .inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        Self::rejected(
            self.mux,
            inner.sender_channel,
            Some(reason),
            Some(description.into()),
        );
        self.mux.flush().await?;

        Ok(())
    }

    /// Access the _context_ of the channel open request.
    pub fn cx(&self) -> &connect::ChannelOpenContext {
        &self
            .inner
            .as_ref()
            .expect("Inner value has been dropped before the outer structure")
            .context
    }
}

impl<'s, IO: Pipe, S: Side> Drop for ChannelOpen<'s, IO, S> {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            Self::rejected(self.mux, inner.sender_channel, None, None);
        }
    }
}
