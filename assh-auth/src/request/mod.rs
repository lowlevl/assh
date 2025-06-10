//! Authentication _request_ mechanics.

use hashbrown::HashSet;

use assh::{service::Request, side::Side, Error, Pipe, Result, Session};
use ssh_packet::{
    arch::{self, Ascii, Utf8},
    crypto::signature,
    trans::DisconnectReason,
    userauth, Packet,
};

mod method;
use method::Method;

// TODO: (feature) Add hostbased authentication.
// TODO: (feature) Add keyboard-interactive authentication.
// TODO: (compliance) Handle the SSH banner in the `request` side.

#[doc(no_inline)]
pub use ssh_key::PrivateKey;

/// The authentication service [`Request`] for sessions.
#[derive(Debug)]
pub struct Auth<R> {
    username: Utf8<'static>,
    service: R,

    methods: HashSet<Method>,
}

impl<R: Request> Auth<R> {
    /// Create an [`Auth`] layer for the provided _username_, to access the provided _service_.
    ///
    /// # Note
    /// 1. The layer always starts with the `none` authentication method
    ///    to discover the methods available on the server.
    /// 2. While the `publickey` method allows for multiple keys,
    ///    the `password` method will only keep the last one provided to [`Self::password`].
    pub fn new(username: impl Into<Utf8<'static>>, service: R) -> Self {
        Self {
            username: username.into(),
            service,

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

    fn next_method(&mut self, continue_with: &arch::NameList) -> Option<Method> {
        self.methods
            .extract_if(|m| {
                continue_with
                    .into_iter()
                    .any(|method| m.as_ascii() == method)
            })
            .next()
    }

    async fn attempt_method<IO: Pipe, S: Side>(
        &mut self,
        session: &mut Session<IO, S>,
        method: &Method,
    ) -> Result<Packet> {
        let build = |method| userauth::Request {
            username: self.username.clone(),
            service_name: R::SERVICE_NAME,
            method,
        };

        match method {
            Method::None => {
                session.send(&build(userauth::Method::None)).await?;

                session.recv().await
            }
            Method::Publickey { key } => {
                let algorithm = key.algorithm();

                // Probe the server to know if this algorithm is implemented.
                session
                    .send(&build(userauth::Method::Publickey {
                        algorithm: algorithm.as_str().as_bytes().into(),
                        blob: key.public_key().to_bytes()?.into(),
                        signature: None,
                    }))
                    .await?;

                let response = session.recv().await?;
                if let Ok(userauth::PkOk { algorithm, blob }) = response.to() {
                    // Actually sign the message with the key to perform real authentication.
                    let signature = signature::Publickey {
                        session_id: session
                            .session_id()
                            .expect("authentication attempted before key-exchange")
                            .into(),
                        username: self.username.as_borrow(),
                        service_name: R::SERVICE_NAME,
                        algorithm: algorithm.as_borrow(),
                        blob: blob.as_borrow(),
                    }
                    .sign(key.as_ref());

                    session
                        .send(&build(userauth::Method::Publickey {
                            algorithm,
                            blob,
                            signature: Some(signature.as_bytes().into()),
                        }))
                        .await?;

                    session.recv().await
                } else {
                    Ok(response)
                }
            }
            Method::Password { password } => {
                session
                    .send(&build(userauth::Method::Password {
                        password: password.as_str().into(),
                        new: None,
                    }))
                    .await?;

                let response = session.recv().await?;
                if let Ok(userauth::PasswdChangereq { prompt: _, .. }) = response.to() {
                    todo!() // TODO: (compliance) Handle the change request case
                } else {
                    Ok(response)
                }
            }
        }
    }
}

impl<R: Request> Request for Auth<R> {
    type Err = R::Err;
    type Ok<IO: Pipe, S: Side> = R::Ok<IO, S>;

    const SERVICE_NAME: Ascii<'static> = crate::SERVICE_NAME;

    async fn on_accept<IO, S>(
        &mut self,
        mut session: Session<IO, S>,
    ) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        let mut method = Method::None;

        loop {
            let response = self.attempt_method(&mut session, &method).await?;

            if response.to::<userauth::Success>().is_ok() {
                break self.service.on_accept(session).await;
            } else if let Ok(userauth::Failure { continue_with, .. }) = response.to() {
                // TODO: (compliance) Take care of partial success

                if let Some(next) = self.next_method(&continue_with) {
                    method = next;
                } else {
                    break Err(Error::from(
                        session
                            .disconnect(
                                DisconnectReason::NoMoreAuthMethodsAvailable,
                                "Exhausted available authentication methods",
                            )
                            .await,
                    )
                    .into());
                };
            } else {
                break Err(Error::from(
                    session
                        .disconnect(
                            DisconnectReason::ProtocolError,
                            format!(
                                "Unexpected message in the context of the `{}` service request",
                                Self::SERVICE_NAME
                            ),
                        )
                        .await,
                )
                .into());
            }
        }
    }
}
