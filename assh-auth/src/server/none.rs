/// The response to the authentication request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// _Accept_ the authentication request.
    Accept,

    /// _Reject_ the authentication request.
    Reject,
}

pub trait None: Send + Sync {
    fn process(&mut self, user: String) -> Response;
}

impl<T: FnMut(String) -> Response + Send + Sync> None for T {
    fn process(&mut self, user: String) -> Response {
        (self)(user)
    }
}

/// A default implementation of the method that rejects all requests.
impl None for () {
    fn process(&mut self, _: String) -> Response {
        Response::Reject
    }
}
