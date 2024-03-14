/// The response to the authentication request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// _Accept_ the authentication request.
    Accept,

    /// _Partially accept_ the authentication request, asking for a password change.
    PasswordExpired {
        /// The prompt displayed to user before the password change.
        prompt: String,
    },

    /// _Reject_ the authentication request.
    Reject,
}

pub trait Password: Send + Sync {
    fn process(&mut self, user: String, password: String, newpassword: Option<String>) -> Response;
}

impl<T: FnMut(String, String, Option<String>) -> Response + Send + Sync> Password for T {
    fn process(&mut self, user: String, password: String, newpassword: Option<String>) -> Response {
        (self)(user, password, newpassword)
    }
}

/// A default implementation of the method that rejects all requests.
impl Password for () {
    fn process(&mut self, _: String, _: String, _: Option<String>) -> Response {
        Response::Reject
    }
}
