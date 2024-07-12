//! The SSH _channel open requests_.

use assh::{side::Side, Pipe};
use futures::SinkExt;
use ssh_packet::{arch::StringUtf8, connect, IntoPacket};

use super::Connect;
use crate::{
    channel::{self, LocalWindow},
    Result,
};

// TODO: Drop implementation ?

// /// The outcome to a sent _channel open request_.
// pub enum ChannelOpenOutcome {
//     /// _Accepted_ the channel open request.
//     Accepted(channel::Channel),

//     /// _Rejected_ the channel open request.
//     Rejected {
//         /// The reason for failure.
//         reason: connect::ChannelOpenFailureReason,

//         /// A textual message to acompany the reason.
//         message: String,
//     },
// }

/// A received _global request_.
pub struct ChannelOpen<'a, IO: Pipe, S: Side> {
    connect: &'a Connect<IO, S>,
    inner: connect::ChannelOpen,
}

impl<'a, IO: Pipe, S: Side> ChannelOpen<'a, IO, S> {
    pub(super) fn new(connect: &'a Connect<IO, S>, inner: connect::ChannelOpen) -> Self {
        Self { connect, inner }
    }

    /// Access the _context_ of the channel open request.
    pub fn cx(&self) -> &connect::ChannelOpenContext {
        &self.inner.context
    }

    /// Accept the channel open request.
    pub async fn accept(self) -> Result<channel::Channel<'a, IO, S>> {
        // TODO: Assess the need for this loop
        let local_id = loop {
            let id = self
                .connect
                .channels
                .iter()
                .map(|id| *id + 1)
                .max()
                .unwrap_or_default();

            if self.connect.channels.insert(id) {
                break id;
            }
        };

        self.connect
            .poller
            .lock()
            .await
            .send(
                connect::ChannelOpenConfirmation {
                    recipient_channel: self.inner.sender_channel,
                    sender_channel: local_id,
                    initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                    maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
                }
                .into_packet(),
            )
            .await?;

        Ok(channel::Channel::new(self.connect, local_id, self.inner))
    }

    /// Reject the channel open request.
    pub async fn reject(
        self,
        reason: connect::ChannelOpenFailureReason,
        description: impl Into<StringUtf8>,
    ) -> Result<()> {
        self.connect
            .poller
            .lock()
            .await
            .send(
                connect::ChannelOpenFailure {
                    recipient_channel: self.inner.sender_channel,
                    reason,
                    description: description.into(),
                    language: Default::default(),
                }
                .into_packet(),
            )
            .await?;

        Ok(())
    }
}
