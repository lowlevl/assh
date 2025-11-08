//! The _channel open requests_ and responses.

use assh::{Pipe, side::Side};
use ssh_packet::{arch::Utf8, connect};

use crate::{
    Result,
    channel::{self, Id, LocalWindow},
    mux::Mux,
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

    inner: Option<connect::ChannelOpen<'static>>,
    id: Id,
}

impl<'s, IO: Pipe, S: Side> ChannelOpen<'s, IO, S> {
    pub(super) fn new(mux: &'s Mux<IO, S>, inner: connect::ChannelOpen<'static>, id: Id) -> Self {
        Self {
            mux,
            inner: Some(inner),
            id,
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
                recipient_channel: self.id.remote(),
                sender_channel: self.id.local(),
                initial_window_size: LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: LocalWindow::MAXIMUM_PACKET_SIZE,
            })
            .await?;

        Ok(channel::Channel::new(
            self.mux,
            self.id.clone(),
            inner.initial_window_size,
            inner.maximum_packet_size,
        ))
    }

    pub(crate) fn rejected(
        mux: &Mux<IO, S>,
        recipient_channel: u32,
        reason: Option<connect::ChannelOpenFailureReason>,
        description: Option<Utf8<'_>>,
    ) {
        mux.feed(&connect::ChannelOpenFailure {
            recipient_channel,
            reason: reason.unwrap_or(connect::ChannelOpenFailureReason::AdministrativelyProhibited),
            description: description
                .unwrap_or_else(|| "Opening channels is disallowed at this time".into()),
            language: Default::default(),
        });
    }

    /// Reject the channel open request.
    pub async fn reject(
        mut self,
        reason: connect::ChannelOpenFailureReason,
        description: impl Into<Utf8<'_>>,
    ) -> Result<()> {
        self.inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        Self::rejected(
            self.mux,
            self.id.remote(),
            Some(reason),
            Some(description.into()),
        );
        self.mux.flush().await?;

        Ok(())
    }

    /// Access the _context_ of the channel open request.
    pub fn cx(&self) -> &connect::ChannelOpenContext<'_> {
        &self
            .inner
            .as_ref()
            .expect("Inner value has been dropped before the outer structure")
            .context
    }
}

impl<'s, IO: Pipe, S: Side> Drop for ChannelOpen<'s, IO, S> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            Self::rejected(self.mux, self.id.remote(), None, None);
        }
    }
}
