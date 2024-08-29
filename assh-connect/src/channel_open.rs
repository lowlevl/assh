//! The _channel open requests_ and responses.

use assh::{side::Side, Pipe};
use ssh_packet::{arch::StringUtf8, connect};

use super::Connect;
use crate::{
    channel::{self, LocalWindow},
    Result,
};

#[doc(no_inline)]
pub use ssh_packet::connect::{ChannelOpenContext, ChannelOpenFailureReason};

// TODO: Drop implementation ?

/// A response to a _channel open request_.
pub enum Response<'r, IO: Pipe, S: Side> {
    /// The request succeeded, with an opened channel.
    Success(channel::Channel<'r, IO, S>),

    /// The request failed.
    Failure {
        /// The reason for failure.
        reason: connect::ChannelOpenFailureReason,

        /// A textual description of the failure.
        description: String,
    },
}

/// A received _channel open request_.
pub struct ChannelOpen<'r, IO: Pipe, S: Side> {
    connect: &'r Connect<IO, S>,
    inner: connect::ChannelOpen,
}

impl<'r, IO: Pipe, S: Side> ChannelOpen<'r, IO, S> {
    pub(super) fn new(connect: &'r Connect<IO, S>, inner: connect::ChannelOpen) -> Self {
        Self { connect, inner }
    }

    /// Access the _context_ of the channel open request.
    pub fn cx(&self) -> &connect::ChannelOpenContext {
        &self.inner.context
    }

    /// Accept the channel open request.
    pub async fn accept(self) -> Result<channel::Channel<'r, IO, S>> {
        let local_id = self.connect.local_id();

        self.connect
            .send(&connect::ChannelOpenConfirmation {
                recipient_channel: self.inner.sender_channel,
                sender_channel: local_id,
                initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
            })
            .await?;

        Ok(channel::Channel::new(
            self.connect,
            local_id,
            self.inner.sender_channel,
            self.inner.initial_window_size,
            self.inner.maximum_packet_size,
        ))
    }

    /// Reject the channel open request.
    pub async fn reject(
        self,
        reason: connect::ChannelOpenFailureReason,
        description: impl Into<StringUtf8>,
    ) -> Result<()> {
        self.connect
            .send(&connect::ChannelOpenFailure {
                recipient_channel: self.inner.sender_channel,
                reason,
                description: description.into(),
                language: Default::default(),
            })
            .await?;

        Ok(())
    }
}
