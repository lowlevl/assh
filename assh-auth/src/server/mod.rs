//! Server-side authentication mechanics.

use assh::{
    service::Handler,
    session::{server::Server, Session, Side},
    Result,
};
use enumset::EnumSet;
use futures::{AsyncBufRead, AsyncWrite};
use ssh_key::{public::PublicKey, Signature};
use ssh_packet::{
    arch::{NameList, StringAscii, StringUtf8},
    cryptography::PublickeySignature,
    trans::{DisconnectReason, ServiceAccept, ServiceRequest},
    userauth,
};

use crate::{CONNECTION_SERVICE_NAME, SERVICE_NAME};

mod method;
use method::Method;

pub mod none;
pub mod password;
pub mod publickey;

/// The authentication service [`Handler`] for sessions.
#[derive(Debug)]
pub struct Auth<N = (), P = (), PK = ()> {
    banner: Option<StringUtf8>,
    // TODO: Add a total attempts counter, to disconnect when exceeded.
    // TODO: Retain methods per user-basis, because each user can attempt all the methods.
    methods: EnumSet<Method>,

    none: N,
    password: P,
    publickey: PK,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            banner: Default::default(),
            methods: Method::None.into(), // always insert the `none` method

            none: (),
            password: (),
            publickey: (),
        }
    }
}

impl Auth {
    /// Create an [`Auth`] layer, rejecting all authentication by default.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<N: none::None, P: password::Password, PK: publickey::Publickey> Auth<N, P, PK> {
    /// Set the authentication banner text to be displayed upon authentication (the string should be `\r\n` terminated).
    pub fn banner(mut self, banner: impl Into<StringUtf8>) -> Self {
        self.banner = Some(banner.into());

        self
    }

    /// Set the authentication handler for the `none` method.
    pub fn none(self, none: impl none::None) -> Auth<impl none::None, P, PK> {
        let Self {
            banner,
            mut methods,
            none: _,
            password,
            publickey,
        } = self;

        methods |= Method::None;

        Auth {
            banner,
            methods,
            none,
            password,
            publickey,
        }
    }

    /// Set the authentication handler for the `password` method.
    pub fn password(
        self,
        password: impl password::Password,
    ) -> Auth<N, impl password::Password, PK> {
        let Self {
            banner,
            mut methods,
            none,
            password: _,
            publickey,
        } = self;

        methods |= Method::Password;

        Auth {
            banner,
            methods,
            none,
            password,
            publickey,
        }
    }

    /// Set the authentication handler for the `publickey` method.
    pub fn publickey(
        self,
        publickey: impl publickey::Publickey,
    ) -> Auth<N, P, impl publickey::Publickey> {
        let Self {
            banner,
            mut methods,
            none,
            password,
            publickey: _,
        } = self;

        methods |= Method::Publickey;

        Auth {
            banner,
            methods,
            none,
            password,
            publickey,
        }
    }

    async fn success(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin + Send, impl Side>,
    ) -> Result<()> {
        session.send(&userauth::Success).await
    }

    async fn failure(
        &self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin + Send, impl Side>,
    ) -> Result<()> {
        session
            .send(&userauth::Failure {
                continue_with: NameList::new(self.methods),
                partial_success: false.into(),
            })
            .await
    }

    async fn handle(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin + Send, impl Side>,
        username: StringUtf8,
        method: userauth::Method,
        service_name: &StringAscii,
    ) -> Result<()> {
        match method {
            userauth::Method::None => {
                tracing::debug!(
                    "Attempt using method `none` for user `{}`",
                    username.as_str()
                );

                match self.none.process(username.to_string()) {
                    none::Response::Accept => self.success(session).await?,
                    none::Response::Reject => self.failure(session).await?,
                }
            }

            userauth::Method::Publickey {
                algorithm,
                blob,
                signature,
            } => {
                tracing::debug!(
                    "Attempt using method `publickey` (signed: {}, algorithm: {}) for user `{}`",
                    signature.is_some(),
                    std::str::from_utf8(&algorithm).unwrap_or("unknown"),
                    username.as_str(),
                );

                let key = PublicKey::from_bytes(&blob);

                match signature {
                    Some(signature) => match key {
                        Ok(key) if key.algorithm().as_str().as_bytes() == algorithm.as_ref() => {
                            let message = PublickeySignature {
                                session_id: &session.session_id().unwrap_or_default().into(),
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
                                self.success(session).await?;
                            } else {
                                // TODO: Does a faked signature needs to cause disconnection ?
                                self.failure(session).await?;
                            }
                        }
                        _ => self.failure(session).await?,
                    },
                    None => {
                        // Authentication has not actually been attempted, so we allow it again.
                        self.methods |= Method::Publickey;

                        if key.is_ok() {
                            session.send(&userauth::PkOk { blob, algorithm }).await?;
                        } else {
                            self.failure(session).await?;
                        }
                    }
                }
            }

            userauth::Method::Password { password, new } => {
                tracing::debug!(
                    "Attempt using method `password` (update: {}) for user `{}`",
                    new.is_some(),
                    username.as_str()
                );

                match self.password.process(
                    username.into_string(),
                    password.into_string(),
                    new.map(StringUtf8::into_string),
                ) {
                    password::Response::Accept => self.success(session).await?,
                    password::Response::PasswordExpired { prompt } => {
                        self.methods |= Method::Password;

                        session
                            .send(&userauth::PasswdChangereq {
                                prompt: prompt.into(),
                                ..Default::default()
                            })
                            .await?;
                    }
                    password::Response::Reject => self.failure(session).await?,
                }
            }

            userauth::Method::Hostbased { .. } => {
                // TODO: Add hostbased authentication.
                unimplemented!("Server-side `hostbased` method is not implemented")
            }

            userauth::Method::KeyboardInteractive { .. } => {
                // TODO: Add keyboard-interactive authentication.
                unimplemented!("Server-side `keyboard-interactive` method is not implemented")
            }
        }

        Ok(())
    }
}

impl<N: none::None, P: password::Password, PK: publickey::Publickey> Handler for Auth<N, P, PK> {
    const SERVICE_NAME: &'static str = crate::SERVICE_NAME;

    async fn proceed(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin + Send, impl Side>,
    ) -> Result<()> {
        let action = match self.state {
            State::Unauthorized => match packet.to() {
                Ok(ServiceRequest { service_name }) if service_name.as_str() == SERVICE_NAME => {
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

            State::Transient => match packet.to() {
                Ok(userauth::Request {
                    username,
                    ref service_name,
                    method,
                }) => {
                    if service_name.as_str() == CONNECTION_SERVICE_NAME {
                        if self.methods.remove(*method.as_ref()) {
                            self.handle(stream, username, method, service_name).await?;
                        } else {
                            self.failure(stream).await?;
                        }

                        Action::Fetch
                    } else {
                        Action::Disconnect {
                            reason: DisconnectReason::ServiceNotAvailable,
                            description: format!(
                                "Unknown service `{}` in authentication request.",
                                service_name.as_str()
                            ),
                        }
                    }
                }
                _ => Action::Disconnect {
                    reason: DisconnectReason::ProtocolError,
                    description: format!(
                        "Unexpected message in the context of the `{SERVICE_NAME}` service."
                    ),
                },
            },

            State::Authorized => Action::Forward(packet),
        };

        Ok(action)
    }
}
