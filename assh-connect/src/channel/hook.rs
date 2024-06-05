use ssh_packet::{arch::StringUtf8, connect};

use crate::channel;

/// A response to a channel open request.
#[derive(Debug)]
pub enum Response {
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

/// An interface to channel open requests.
pub trait Hook {
    /// Process the channel open request.
    fn process(
        &mut self,
        context: connect::ChannelOpenContext,
        channel: channel::Channel,
    ) -> Response;
}

impl<T: FnMut(connect::ChannelOpenContext, channel::Channel) -> Response> Hook for T {
    fn process(
        &mut self,
        context: connect::ChannelOpenContext,
        channel: channel::Channel,
    ) -> Response {
        (self)(context, channel)
    }
}

/// A default implementation of the method that rejects all requests.
impl Hook for () {
    fn process(&mut self, _: connect::ChannelOpenContext, _: channel::Channel) -> Response {
        Response::Reject {
            reason: connect::ChannelOpenFailureReason::AdministrativelyProhibited,
            description: "The channel opening is currently disabled".into(),
        }
    }
}
