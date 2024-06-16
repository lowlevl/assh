//! The SSH _global request_ hook.

use ssh_packet::connect;

/// The response to a _global request_.
#[derive(Debug)]
pub enum GlobalRequest {
    /// _Accepted_ global request.
    Accepted,

    /// _Accepted_ global request, with a bound port.
    AcceptedPort(u32),

    /// _Rejected_ the global request.
    Rejected,
}

/// An outcome to a global request [`Hook`].
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// _Accept_ the global request, returning the port number.
    Accept {
        /// Port that was bound.
        bound_port: u32,
    },

    /// _Reject_ the global request.
    Reject,
}

/// A hook on global requests.
pub trait Hook {
    /// Process the global request.
    fn on_request(&mut self, context: connect::GlobalRequestContext) -> Outcome;
}

impl<T: FnMut(connect::GlobalRequestContext) -> Outcome> Hook for T {
    fn on_request(&mut self, context: connect::GlobalRequestContext) -> Outcome {
        (self)(context)
    }
}

/// A default implementation of the method that rejects all requests.
impl Hook for () {
    fn on_request(&mut self, _: connect::GlobalRequestContext) -> Outcome {
        Outcome::Reject
    }
}
