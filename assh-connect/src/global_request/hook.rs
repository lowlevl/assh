use ssh_packet::connect;

/// A response to a global request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// _Accept_ the global request.
    Accept,

    /// _Reject_ the global request.
    Reject,
}

/// An interface to global requests.
pub trait Hook {
    /// Process the global request.
    fn process(&mut self, context: connect::GlobalRequestContext) -> Response;
}

impl<T: FnMut(connect::GlobalRequestContext) -> Response> Hook for T {
    fn process(&mut self, context: connect::GlobalRequestContext) -> Response {
        (self)(context)
    }
}

/// A default implementation of the method that rejects all requests.
impl Hook for () {
    fn process(&mut self, _: connect::GlobalRequestContext) -> Response {
        Response::Reject
    }
}
