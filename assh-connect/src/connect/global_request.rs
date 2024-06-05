//! The SSH _global request_ hook.

use ssh_packet::connect;

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
    fn process(&mut self, context: connect::GlobalRequestContext) -> Outcome;
}

impl<T: FnMut(connect::GlobalRequestContext) -> Outcome> Hook for T {
    fn process(&mut self, context: connect::GlobalRequestContext) -> Outcome {
        (self)(context)
    }
}

/// A default implementation of the method that rejects all requests.
impl Hook for () {
    fn process(&mut self, _: connect::GlobalRequestContext) -> Outcome {
        Outcome::Reject
    }
}
