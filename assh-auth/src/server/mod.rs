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

pub mod none;
pub mod password;
pub mod publickey;

/// The response to the authentication request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// _Accept_ the authentication request.
    Accept,

    /// _Reject_ the authentication request.
    Reject,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Unauthorized,

    Transient,

    Authorized,
}

/// The authentication [`Layer`] for server-side sessions.
#[derive(Debug)]
pub struct Auth<N = (), P = (), PK = ()> {
    state: State,

    banner: Option<StringUtf8>,
    methods: EnumSet<Method>,

    none: N,
    password: P,
    publickey: PK,
}

impl Auth {
    /// Create an [`Auth`] layer from allowed `methods`.
    pub fn new(methods: impl Into<EnumSet<Method>>) -> Self {
        Self {
            state: Default::default(),

            banner: Default::default(),
            methods: methods.into() | Method::None, // always insert the `none` method

            none: (),
            password: (),
            publickey: (),
        }
    }
}

impl<N, P, PK> Auth<N, P, PK> {
    pub fn banner(mut self, banner: impl Into<StringUtf8>) -> Self {
        self.banner = Some(banner.into());

        self
    }

    pub fn none<T>(self, none: T) -> Auth<T, P, PK> {
        let Self {
            state,
            banner,
            methods,
            none: _,
            password,
            publickey,
        } = self;

        Auth {
            state,
            banner,
            methods,
            none,
            password,
            publickey,
        }
    }

    pub fn password<T>(self, password: T) -> Auth<N, T, PK> {
        let Self {
            state,
            banner,
            methods,
            none,
            password: _,
            publickey,
        } = self;

        Auth {
            state,
            banner,
            methods,
            none,
            password,
            publickey,
        }
    }

    pub fn publickey<T>(self, publickey: T) -> Auth<N, P, T> {
        let Self {
            state,
            banner,
            methods,
            none,
            password,
            publickey: _,
        } = self;

        Auth {
            state,
            banner,
            methods,
            none,
            password,
            publickey,
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

impl<N: none::None, P: password::Password, PK: publickey::Publickey> Layer<Server>
    for Auth<N, P, PK>
{
    async fn on_recv(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
        packet: Packet,
    ) -> Result<Action> {
        Ok(match self.state {
            State::Unauthorized => match packet.to::<ServiceRequest>().ok() {
                Some(ServiceRequest { service_name }) if service_name.as_str() == SERVICE_NAME => {
                    tracing::debug!("Received authentication request from peer");

                    stream.send(&ServiceAccept { service_name }).await?;

                    if let Some(message) = self.banner.take() {
                        tracing::debug!("Sending authentication banner to peer");

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
                        tracing::debug!(
                            "Attempt using method `none` for user `{}`",
                            username.as_str()
                        );

                        match self.none.process(username.to_string()) {
                            none::Response::Accept => self.success(stream).await?,
                            none::Response::Reject => self.failure(stream).await?,
                        }

                        Action::Fetch
                    }
                    userauth::Method::Publickey {
                        algorithm,
                        blob,
                        signature,
                    } if self.is_available(&method) => {
                        tracing::debug!(
                            "Attempt using method `publickey` (signed: {}, algorithm: {}) for user `{}`",
                            signature.is_some(),
                            std::str::from_utf8(&algorithm).unwrap_or("unknown"),
                            username.as_str(),
                        );

                        let key = PublicKey::from_bytes(&blob);

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
                                        algorithm: &algorithm,
                                        blob: &blob,
                                    };

                                    if message
                                        .verify(&key, &Signature::try_from(signature.as_ref())?)
                                        .is_ok()
                                        && self.publickey.process(username.to_string(), key)
                                            == publickey::Response::Accept
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
                                    stream.send(&userauth::PkOk { blob, algorithm }).await?;
                                } else {
                                    self.failure(stream).await?;
                                }
                            }
                        }

                        Action::Fetch
                    }
                    userauth::Method::Password { password, new } if self.is_available(&method) => {
                        tracing::debug!(
                            "Attempt using method `password` (renew: {}) for user `{}`",
                            new.is_some(),
                            username.as_str()
                        );

                        match self.password.process(
                            username.into_string(),
                            password.into_string(),
                            new.map(StringUtf8::into_string),
                        ) {
                            password::Response::Accept => self.success(stream).await?,
                            password::Response::PasswordExpired => todo!(),
                            password::Response::Reject => self.failure(stream).await?,
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
