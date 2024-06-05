//! The SSH _channel open request_ hook.

use ssh_packet::{arch::StringUtf8, connect};

use crate::channel;

/// An outcome to a channel open [`Hook`].
#[derive(Debug)]
pub enum Outcome {
    /// _Accept_ the channel open request.
    Accept,

    /// _Reject_ the channel open request.
    Reject {
        /// Reason for rejection.
        reason: connect::ChannelOpenFailureReason,

        /// A textual description of the reason.
        description: StringUtf8,
    },
}

/// A hook on channel open requests.
pub trait Hook {
    /// Process the channel open request.
    fn process(
        &mut self,
        context: connect::ChannelOpenContext,
        channel: channel::Channel,
    ) -> Outcome;
}

impl<T: FnMut(connect::ChannelOpenContext, channel::Channel) -> Outcome> Hook for T {
    fn process(
        &mut self,
        context: connect::ChannelOpenContext,
        channel: channel::Channel,
    ) -> Outcome {
        (self)(context, channel)
    }
}

/// A default implementation of the method that rejects all requests.
impl Hook for () {
    fn process(&mut self, _: connect::ChannelOpenContext, _: channel::Channel) -> Outcome {
        Outcome::Reject {
            reason: connect::ChannelOpenFailureReason::AdministrativelyProhibited,
            description: "The channel opening is currently disabled".into(),
        }
    }
}
