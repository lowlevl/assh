//! Client-side authentication mechanics.

use hashbrown::HashSet;

use assh::{
    layer::{Action, Layer},
    session::client::Client,
    stream::{Packet, Stream},
    Result,
};
use futures::{AsyncBufRead, AsyncWrite};

mod method;
use method::Method;

// TODO: Add hostbased authentication.
// TODO: Add keyboard-interactive authentication.

#[doc(no_inline)]
pub use ssh_key::PrivateKey;
use ssh_packet::{
    cryptography::PublickeySignature,
    trans::{DisconnectReason, ServiceAccept, ServiceRequest},
    userauth,
};

use crate::SERVICE_NAME;

#[derive(Debug, Default)]
enum State {
    #[default]
    Unauthorized,
    Transient,
    Authorized,
}

/// The authentication [`Layer`] for client-side sessions.
#[derive(Debug)]
pub struct Auth {
    state: State,

    username: String,
    methods: HashSet<Method>,
}

impl Auth {
    /// Create an [`Auth`] layer for the provided _username_.
    ///
    /// # Note
    /// The layer always starts with the `none` authentication method
    /// to discover the methods available on the server.
    ///
    /// Also while the `publickey` method allows for multiple tries,
    /// the `password` method will only keep the last one provided to [`Self::password`].
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            state: Default::default(),
            username: username.into(),
            methods: Default::default(),
        }
    }

    /// Attempt to authenticate with the `password` method.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.methods.replace(Method::Password {
            password: password.into(),
        });

        self
    }

    /// Attempt to authenticate with the `publickey` method.
    pub fn publickey(mut self, key: impl Into<PrivateKey>) -> Self {
        self.methods.replace(Method::Publickey {
            key: key.into().into(),
        });

        self
    }

    async fn attempt(&mut self, method: Method) -> Result<()> {
        match method {
            Method::None => todo!(),
            Method::Publickey { key } => todo!(),
            Method::Password { password } => todo!(),
        }

        Ok(())
    }
}

impl Layer<Client> for Auth {
    async fn on_kex(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        stream
            .send(&ServiceRequest {
                service_name: SERVICE_NAME.into(),
            })
            .await?;

        Ok(())
    }

    async fn on_recv(
        &mut self,
        _stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
        packet: Packet,
    ) -> Result<Action> {
        Ok(match self.state {
            State::Unauthorized => match packet.to() {
                Ok(ServiceAccept { service_name }) if service_name.as_str() == SERVICE_NAME => {
                    self.attempt(Method::None).await?;

                    self.state = State::Transient;
                    Action::Fetch
                }
                _ => Action::Disconnect {
                    reason: DisconnectReason::ProtocolError,
                    description: format!(
                        "Unexpected message in the context of the `{SERVICE_NAME}` service."
                    ),
                },
            },
            State::Transient => {
                if let Ok(userauth::Success) = packet.to() {
                    self.state = State::Authorized;
                    Action::Fetch
                } else if let Ok(userauth::Failure { continue_with, .. }) = packet.to() {
                    if let Some(method) = self
                        .methods
                        .extract_if(|m| {
                            continue_with.into_iter().any(|method| m.as_ref() == method)
                        })
                        .next()
                    {
                        self.attempt(method).await?;

                        Action::Fetch
                    } else {
                        Action::Disconnect {
                            reason: DisconnectReason::NoMoreAuthMethodsAvailable,
                            description:
                                "Authentication methods exhausted for the current session.".into(),
                        }
                    }
                } else {
                    Action::Disconnect {
                        reason: DisconnectReason::ProtocolError,
                        description: format!(
                            "Unexpected message in the context of the `{SERVICE_NAME}` service."
                        ),
                    }
                }
            }
            State::Authorized => Action::Forward(packet),
        })
    }
}
