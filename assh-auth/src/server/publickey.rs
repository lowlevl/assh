use ssh_key::PublicKey;

/// The response to the authentication request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// _Accept_ the authentication request.
    Accept,

    /// _Reject_ the authentication request.
    Reject,
}

pub trait Publickey: Send + Sync {
    fn process(&mut self, user: String, key: PublicKey) -> Response;
}

impl<T: FnMut(String, PublicKey) -> Response + Send + Sync> Publickey for T {
    fn process(&mut self, user: String, key: PublicKey) -> Response {
        (self)(user, key)
    }
}

/// A default implementation of the method that rejects all requests.
impl Publickey for () {
    fn process(&mut self, _: String, _: PublicKey) -> Response {
        Response::Reject
    }
}
