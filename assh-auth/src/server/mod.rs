//! Server-side authentication layer.

use assh::{
    layer::{Action, Layer},
    session::server::Server,
    stream::{Packet, Stream},
    Result,
};
use convert_case::{Case, Casing};
use futures::{AsyncBufRead, AsyncWrite};
use ssh_packet::{
    arch::{NameList, StringUtf8},
    trans::{DisconnectReason, ServiceAccept, ServiceRequest},
    userauth::{AuthBanner, AuthFailure, AuthMethod, AuthRequest},
};

use crate::{Methods, CONNECTION_SERVICE_NAME, SERVICE_NAME};

#[derive(Debug, Default)]
enum State {
    #[default]
    Unauthorized,
    Transient,
    Authorized,
}

#[derive(Debug, Default)]
pub struct Auth {
    state: State,

    banner: Option<StringUtf8>,
    methods: Methods,
}

impl Auth {
    pub fn new(banner: Option<impl Into<StringUtf8>>, methods: Methods) -> Self {
        Self {
            state: Default::default(),

            banner: banner.map(Into::into),
            methods,
        }
    }

    pub async fn failure(
        &self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin>,
    ) -> Result<()> {
        stream
            .send(&AuthFailure {
                continue_with: NameList::new(
                    &self
                        .methods
                        .iter_names()
                        .map(|(name, _)| name.to_case(Case::Kebab))
                        .collect::<Vec<_>>(),
                ),
                partial_success: false.into(),
            })
            .await
    }
}

impl Layer<Server> for Auth {
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
                            .send(&AuthBanner {
                                message,
                                language: Default::default(),
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

            State::Transient => match packet.to::<AuthRequest>().ok() {
                Some(AuthRequest {
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

                    AuthMethod::None if self.methods.contains(Methods::NONE) => {
                        self.methods.remove(Methods::NONE);

                        self.failure(stream).await?;

                        Action::Fetch
                    }
                    AuthMethod::Publickey { .. } if self.methods.contains(Methods::PUBLICKEY) => {
                        self.methods.remove(Methods::PUBLICKEY);

                        self.failure(stream).await?;

                        Action::Fetch
                    }
                    AuthMethod::Password { .. } if self.methods.contains(Methods::PASSWORD) => {
                        self.methods.remove(Methods::PASSWORD);

                        self.failure(stream).await?;

                        Action::Fetch
                    }
                    AuthMethod::Hostbased { .. } if self.methods.contains(Methods::HOSTBASED) => {
                        self.methods.remove(Methods::HOSTBASED);

                        self.failure(stream).await?;

                        Action::Fetch
                    }
                    AuthMethod::KeyboardInteractive { .. }
                        if self.methods.contains(Methods::KEYBOARD_INTERACTIVE) =>
                    {
                        self.methods.remove(Methods::KEYBOARD_INTERACTIVE);

                        self.failure(stream).await?;

                        Action::Fetch
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
