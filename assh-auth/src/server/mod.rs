//! Server-side authentication mechanics.

use assh::{
    layer::{Action, Layer},
    session::server::Server,
    stream::{Packet, Stream},
    Result,
};
use enumset::EnumSet;
use futures::{AsyncBufRead, AsyncWrite};
use ssh_packet::{
    arch::{NameList, StringUtf8},
    trans::{DisconnectReason, ServiceAccept, ServiceRequest},
    userauth,
};

use crate::{Method, CONNECTION_SERVICE_NAME, SERVICE_NAME};

/// The response to the authentication request.
#[derive(Debug)]
pub enum Response {
    /// _Accept_ the authentication request.
    Accept,

    /// _Reject_ the authentication request.
    Reject,
}

#[derive(Debug)]
enum State {
    Unauthorized,
    Transient,
    Authorized,
}

/// The authentication [`Layer`] for server-side sessions.
#[derive(Debug)]
pub struct Auth<F> {
    state: State,

    banner: Option<StringUtf8>,
    methods: EnumSet<Method>,
    handler: F,
}

impl<F> Auth<F> {
    /// Create an [`Auth`] layer from the `banner` text, allowed `methods` and an authentication `handler`.
    pub fn new(
        banner: Option<impl Into<StringUtf8>>,
        methods: EnumSet<Method>,
        handler: F,
    ) -> Self {
        Self {
            state: State::Unauthorized,

            banner: banner.map(Into::into),
            methods: methods | Method::None, // always insert the `none` method
            handler,
        }
    }

    async fn success(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
    ) -> Result<()> {
        self.state = State::Authorized;

        stream.send(&userauth::Success).await
    }

    async fn failure(
        &self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
    ) -> Result<()> {
        stream
            .send(&userauth::Failure {
                continue_with: NameList::new(self.methods),
                partial_success: false.into(),
            })
            .await
    }

    fn is_available(&mut self, method: impl Into<Method>) -> bool {
        let method = method.into();

        self.methods
            .contains(method)
            .then(|| self.methods.remove(method))
            .is_some()
    }
}

impl<F: FnMut(String, userauth::Method) -> Response> Layer<Server> for Auth<F> {
    async fn on_recv(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
        packet: Packet,
    ) -> Result<Action> {
        Ok(match self.state {
            State::Unauthorized => match packet.to::<ServiceRequest>().ok() {
                Some(ServiceRequest { service_name }) if service_name.as_str() == SERVICE_NAME => {
                    stream.send(&ServiceAccept { service_name }).await?;

                    if let Some(message) = self.banner.take() {
                        stream
                            .send(&userauth::Banner {
                                message,
                                ..Default::default()
                            })
                            .await?;
                    }

                    self.state = State::Transient;

                    Action::Fetch
                }
                _ => Action::Disconnect {
                    reason: DisconnectReason::ByApplication,
                    description: "This server requires authentication.".into(),
                },
            },

            State::Transient => match packet.to::<userauth::Request>().ok() {
                Some(userauth::Request {
                    username,
                    service_name,
                    method,
                }) => match method {
                    _ if service_name.as_str() != CONNECTION_SERVICE_NAME => Action::Disconnect {
                        reason: DisconnectReason::ServiceNotAvailable,
                        description: format!(
                            "Unknown service `{}` in authentication request.",
                            service_name.as_str()
                        ),
                    },

                    userauth::Method::None if self.is_available(&method) => {
                        match (self.handler)(username.into_string(), method) {
                            Response::Accept => self.success(stream).await?,
                            Response::Reject => self.failure(stream).await?,
                        }

                        Action::Fetch
                    }
                    userauth::Method::Publickey { .. } if self.is_available(&method) => {
                        match (self.handler)(username.into_string(), method) {
                            Response::Accept => self.success(stream).await?,
                            Response::Reject => self.failure(stream).await?,
                        }

                        Action::Fetch
                    }
                    userauth::Method::Password { .. } if self.is_available(&method) => {
                        match (self.handler)(username.into_string(), method) {
                            Response::Accept => self.success(stream).await?,
                            Response::Reject => self.failure(stream).await?,
                        }

                        Action::Fetch
                    }
                    userauth::Method::Hostbased { .. } if self.is_available(&method) => {
                        unimplemented!()
                    }
                    userauth::Method::KeyboardInteractive { .. } if self.is_available(&method) => {
                        unimplemented!()
                    }

                    _ => Action::Disconnect {
                        reason: DisconnectReason::NoMoreAuthMethodsAvailable,
                        description: "Authentication methods exhausted for the current session."
                            .into(),
                    },
                },
                None => Action::Disconnect {
                    reason: DisconnectReason::ProtocolError,
                    description: format!(
                        "Unexpected message in the context of the `{SERVICE_NAME}` service."
                    ),
                },
            },

            State::Authorized => Action::Forward(packet),
        })
    }
}
