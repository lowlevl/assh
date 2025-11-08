//! Authentication _handling_ mechanics.

use assh::{Error, Pipe, Result, Session, service::Handler, side::Side};
use enumset::EnumSet;
use ssh_key::{Signature, public::PublicKey};
use ssh_packet::{
    arch::{Ascii, NameList, Utf8},
    crypto::signature,
    trans::DisconnectReason,
    userauth,
};

mod method;
use method::Method;

pub mod none;
pub mod password;
pub mod publickey;

#[derive(Debug, PartialEq)]
enum Attempt {
    Success,
    Partial,
    Failure,
    Continue,
}

/// The authentication service [`Handler`] for sessions.
#[derive(Debug)]
pub struct Auth<H, N = (), P = (), PK = ()> {
    banner: Option<Utf8<'static>>,
    // TODO: (compliance) Add a total attempts counter, to disconnect when exceeded.
    // TODO: (compliance) Retain methods per user-basis, because each user can attempt all the methods.
    methods: EnumSet<Method>,

    handler: H,

    none: N,
    password: P,
    publickey: PK,
}

impl<H> Auth<H>
where
    H: Handler,
{
    /// Create an [`Auth`] layer, rejecting all authentication by default.
    pub fn new(service: H) -> Self {
        Self {
            banner: Default::default(),
            methods: Method::None.into(), // always insert the `none` method

            handler: service,

            none: (),
            password: (),
            publickey: (),
        }
    }
}

impl<H, N, P, PK> Auth<H, N, P, PK>
where
    H: Handler,
    N: none::None,
    P: password::Password,
    PK: publickey::Publickey,
{
    /// Set the authentication banner text to be displayed upon authentication (the string should be `\r\n` terminated).
    pub fn banner(mut self, banner: impl Into<Utf8<'static>>) -> Self {
        self.banner = Some(banner.into());

        self
    }

    /// Set the authentication handler for the `none` method.
    pub fn none(self, none: impl none::None) -> Auth<H, impl none::None, P, PK> {
        let Self {
            banner,
            mut methods,
            handler,
            none: _,
            password,
            publickey,
        } = self;

        methods |= Method::None;

        Auth {
            banner,
            methods,
            handler,
            none,
            password,
            publickey,
        }
    }

    /// Set the authentication handler for the `password` method.
    pub fn password(
        self,
        password: impl password::Password,
    ) -> Auth<H, N, impl password::Password, PK> {
        let Self {
            banner,
            mut methods,
            handler,
            none,
            password: _,
            publickey,
        } = self;

        methods |= Method::Password;

        Auth {
            banner,
            methods,
            handler,
            none,
            password,
            publickey,
        }
    }

    /// Set the authentication handler for the `publickey` method.
    pub fn publickey(
        self,
        publickey: impl publickey::Publickey,
    ) -> Auth<H, N, P, impl publickey::Publickey> {
        let Self {
            banner,
            mut methods,
            handler,
            none,
            password,
            publickey: _,
        } = self;

        methods |= Method::Publickey;

        Auth {
            banner,
            methods,
            handler,
            none,
            password,
            publickey,
        }
    }

    async fn handle_attempt<IO: Pipe, S: Side>(
        &mut self,
        session: &mut Session<IO, S>,
        username: Utf8<'_>,
        method: userauth::Method<'_>,
        service_name: &Ascii<'_>,
    ) -> Result<Attempt> {
        Ok(match method {
            userauth::Method::None => {
                tracing::debug!("Attempt using method `none` for user `{username}`");

                match self.none.process(username.into_string()) {
                    none::Response::Accept => Attempt::Success,
                    none::Response::Reject => Attempt::Failure,
                }
            }

            userauth::Method::Publickey {
                algorithm,
                blob,
                signature,
            } => {
                tracing::debug!(
                    "Attempt using method `publickey` (signed: {}, algorithm: {}) for user `{username}`",
                    signature.is_some(),
                    std::str::from_utf8(&algorithm).unwrap_or("unknown"),
                );

                let key = PublicKey::from_bytes(&blob);

                match signature {
                    None => {
                        // Authentication has not actually been attempted, so we allow it again.
                        self.methods |= Method::Publickey;

                        if key.is_ok() {
                            session.send(&userauth::PkOk { blob, algorithm }).await?;

                            Attempt::Continue
                        } else {
                            Attempt::Failure
                        }
                    }
                    Some(signature) => match key {
                        Ok(key) if key.algorithm().as_str().as_bytes() == algorithm.as_ref() => {
                            let message = signature::Publickey {
                                session_id: session
                                    .session_id()
                                    .expect("authentication attempted before key-exchange")
                                    .into(),
                                username: username.as_borrow(),
                                service_name: service_name.as_borrow(),
                                algorithm,
                                blob,
                            };

                            if message
                                .verify(&key, &Signature::try_from(signature.as_ref())?)
                                .is_ok()
                                && self.publickey.process(username.into_string(), key)
                                    == publickey::Response::Accept
                            {
                                Attempt::Success
                            } else {
                                // TODO: (reliability) Does a faked signature needs to cause disconnection ?
                                Attempt::Failure
                            }
                        }
                        _ => Attempt::Failure,
                    },
                }
            }

            userauth::Method::Password { password, new } => {
                tracing::debug!(
                    "Attempt using method `password` (update: {}) for user `{username}`",
                    new.is_some(),
                );

                match self.password.process(
                    username.into_string(),
                    password.into_string(),
                    new.map(Utf8::into_string),
                ) {
                    password::Response::Accept => Attempt::Success,
                    password::Response::PasswordExpired { prompt } => {
                        self.methods |= Method::Password;

                        session
                            .send(&userauth::PasswdChangereq {
                                prompt: prompt.into(),
                                ..Default::default()
                            })
                            .await?;

                        Attempt::Continue
                    }
                    password::Response::Reject => Attempt::Failure,
                }
            }

            userauth::Method::Hostbased { .. } => {
                // TODO: (feature) Add hostbased authentication.
                todo!("Server-side `hostbased` method is not implemented")
            }

            userauth::Method::KeyboardInteractive { .. } => {
                // TODO: (feature) Add keyboard-interactive authentication.
                todo!("Server-side `keyboard-interactive` method is not implemented")
            }
        })
    }
}

impl<H: Handler, N: none::None, P: password::Password, PK: publickey::Publickey> Handler
    for Auth<H, N, P, PK>
{
    type Err = H::Err;
    type Ok<IO: Pipe, S: Side> = H::Ok<IO, S>;

    const SERVICE_NAME: Ascii<'static> = crate::SERVICE_NAME;

    async fn on_request<IO, S>(
        &mut self,
        mut session: Session<IO, S>,
    ) -> Result<Self::Ok<IO, S>, Self::Err>
    where
        IO: Pipe,
        S: Side,
    {
        if let Some(message) = self.banner.take() {
            session
                .send(&userauth::Banner {
                    message,
                    ..Default::default()
                })
                .await?;
        }

        loop {
            if let Ok(userauth::Request {
                username,
                service_name,
                method,
            }) = session.recv().await?.to()
            {
                if self.methods.remove(*method.as_ref()) {
                    match self
                        .handle_attempt(&mut session, username, method, &service_name)
                        .await?
                    {
                        Attempt::Success => {
                            break if service_name == H::SERVICE_NAME {
                                session.send(&userauth::Success).await?;

                                self.handler.on_request(session).await
                            } else {
                                Err(Error::from(
                                    session
                                        .disconnect(
                                            DisconnectReason::ServiceNotAvailable,
                                            "Requested service is unknown",
                                        )
                                        .await,
                                )
                                .into())
                            };
                        }
                        attempt @ Attempt::Failure | attempt @ Attempt::Partial => {
                            session
                                .send(&userauth::Failure {
                                    continue_with: NameList::from_iter(
                                        self.methods.iter().map(Method::to_ascii),
                                    ),
                                    partial_success: (attempt == Attempt::Partial).into(),
                                })
                                .await?;
                        }
                        Attempt::Continue => (),
                    }
                } else {
                    session
                        .send(&userauth::Failure {
                            continue_with: NameList::from_iter(
                                self.methods.iter().map(Method::to_ascii),
                            ),
                            partial_success: false.into(),
                        })
                        .await?;
                }
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
