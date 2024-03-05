//! Server-side authentication mechanics.

use assh::{
    layer::{Action, Layer},
    session::server::Server,
    stream::{Packet, Stream},
    Result,
};
use enumset::EnumSet;
use futures::{AsyncBufRead, AsyncWrite};
use ssh_key::{public::PublicKey, Signature};
use ssh_packet::{
    arch::{NameList, StringUtf8},
    cryptography::PublickeySignature,
    trans::{DisconnectReason, ServiceAccept, ServiceRequest},
    userauth,
};

use crate::{Method, CONNECTION_SERVICE_NAME, SERVICE_NAME};

/// The response to the authentication request.
#[derive(Debug, PartialEq, Eq)]
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
        methods: impl Into<EnumSet<Method>>,
        handler: F,
    ) -> Self {
        Self {
            state: State::Unauthorized,

            banner: banner.map(Into::into),
            methods: methods.into() | Method::None, // always insert the `none` method
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

impl<F: FnMut(String, userauth::Method) -> Response + Send + Sync> Layer<Server> for Auth<F> {
    async fn on_recv(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
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
                    ref service_name,
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
                        match (self.handler)(username.to_string(), method) {
                            Response::Accept => self.success(stream).await?,
                            Response::Reject => self.failure(stream).await?,
                        }

                        Action::Fetch
                    }
                    userauth::Method::Publickey {
                        ref algorithm,
                        ref blob,
                        ref signature,
                    } if self.is_available(&method) => {
                        let key = PublicKey::from_bytes(blob);

                        match signature {
                            Some(signature) => match key {
                                Ok(key)
                                    if key.algorithm().as_str().as_bytes()
                                        == algorithm.as_ref() =>
                                {
                                    let message = PublickeySignature {
                                        session_id: &stream.session_id().unwrap_or_default().into(),
                                        username: &username,
                                        service_name,
                                        algorithm,
                                        blob,
                                    };

                                    if message
                                        .verify(&key, &Signature::try_from(signature.as_ref())?)
                                        .is_ok()
                                        && (self.handler)(username.to_string(), method)
                                            == Response::Accept
                                    {
                                        self.success(stream).await?;
                                    } else {
                                        self.failure(stream).await?;
                                    }
                                }
                                _ => self.failure(stream).await?,
                            },
                            None => {
                                // Authentication has not actually been attempted, so we allow it again.
                                self.methods |= Method::Publickey;

                                if key.is_ok() {
                                    stream
                                        .send(&userauth::PkOk {
                                            blob: blob.clone(),
                                            algorithm: algorithm.clone(),
                                        })
                                        .await?;
                                } else {
                                    self.failure(stream).await?;
                                }
                            }
                        }

                        Action::Fetch
                    }
                    userauth::Method::Password { .. } if self.is_available(&method) => {
                        match (self.handler)(username.to_string(), method) {
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
