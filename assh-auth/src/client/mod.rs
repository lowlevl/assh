//! Client-side authentication mechanics.

use std::collections::HashSet;

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
use ssh_packet::{cryptography::PublickeySignature, userauth};

#[derive(Debug, Default)]
enum State {
    #[default]
    Unauthorized,
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
}

impl Layer<Client> for Auth {
    async fn on_kex(
        &mut self,
        stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
    ) -> Result<()> {
        match self.state {
            State::Unauthorized => {
                let mut attempt = Method::None;

                loop {
                    let response = match attempt {
                        Method::None => {
                            stream
                                .send(&userauth::Request {
                                    username: self.username.clone().into(),
                                    service_name: crate::CONNECTION_SERVICE_NAME.into(),
                                    method: userauth::Method::None,
                                })
                                .await?;

                            stream.recv().await?
                        }
                        Method::Password { ref password } => {
                            stream
                                .send(&userauth::Request {
                                    username: self.username.clone().into(),
                                    service_name: crate::CONNECTION_SERVICE_NAME.into(),
                                    method: userauth::Method::Password {
                                        password: password.into(),
                                        new: None,
                                    },
                                })
                                .await?;

                            stream.recv().await?
                        }
                        Method::Publickey { ref key } => {
                            stream
                                .send(&userauth::Request {
                                    username: self.username.clone().into(),
                                    service_name: crate::CONNECTION_SERVICE_NAME.into(),
                                    method: userauth::Method::Publickey {
                                        algorithm: key.algorithm().as_str().into(),
                                        blob: key.public_key().to_bytes()?.into(),
                                        signature: None,
                                    },
                                })
                                .await?;

                            let response = stream.recv().await?;
                            if response.to::<userauth::PkOk>().is_err() {
                                response
                            } else {
                                stream
                                    .send(&userauth::Request {
                                        username: self.username.clone().into(),
                                        service_name: crate::CONNECTION_SERVICE_NAME.into(),
                                        method: userauth::Method::Publickey {
                                            algorithm: key.algorithm().as_str().into(),
                                            blob: key.public_key().to_bytes()?.into(),
                                            signature: Some(
                                                PublickeySignature {
                                                    session_id: &stream
                                                        .session_id()
                                                        .unwrap_or_default()
                                                        .into(),
                                                    username: &self.username.clone().into(),
                                                    service_name: &crate::CONNECTION_SERVICE_NAME
                                                        .into(),
                                                    algorithm: &key.algorithm().as_str().into(),
                                                    blob: &key.public_key().to_bytes()?.into(),
                                                }
                                                .sign(&**key)
                                                .as_bytes()
                                                .into(),
                                            ),
                                        },
                                    })
                                    .await?;

                                stream.recv().await?
                            }
                        }
                    };

                    if let Ok(userauth::Success) = response.to() {
                        self.state = State::Authorized;

                        break Ok(());
                    } else if let Ok(userauth::Failure { continue_with, .. }) = response.to() {
                        // TODO: Improve the removal of method without cloning.
                        if let Some(method) = continue_with
                            .into_iter()
                            .flat_map(|name| self.methods.iter().find(|m| m.as_ref() == name))
                            .next()
                            .cloned()
                        {
                            self.methods.remove(&method);

                            attempt = method;
                            continue;
                        } else {
                            // TODO: Get rid of this panic.
                            panic!("Methods exhausted");
                        }
                    } else {
                        // TODO: Get rid of this panic.
                        panic!("Unexpected packet in authentication context");
                    }
                }
            }
            State::Authorized => Ok(()),
        }
    }

    async fn on_recv(
        &mut self,
        _stream: &mut Stream<impl AsyncBufRead + AsyncWrite + Unpin + Send>,
        packet: Packet,
    ) -> Result<Action> {
        match self.state {
            State::Unauthorized => unreachable!("Authentication has not yet been performed, while `on_kex` should be called before."),
            State::Authorized => Ok(Action::Forward(packet)),
        }
    }
}
