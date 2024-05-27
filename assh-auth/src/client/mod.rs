//! Client-side authentication mechanics.

use hashbrown::HashSet;

use assh::{
    service::Request,
    session::{Session, Side},
    Result,
};
use futures::{AsyncBufRead, AsyncWrite};

mod method;
use method::Method;

// TODO: Add hostbased authentication.
// TODO: Add keyboard-interactive authentication.

#[doc(no_inline)]
pub use ssh_key::PrivateKey;
use ssh_packet::{arch, trans::DisconnectReason, userauth};

/// The authentication service [`Request`] for sessions.
#[derive(Debug)]
pub struct Auth<R> {
    username: String,
    service: R,

    methods: HashSet<Method>,
}

impl<R> Auth<R> {
    /// Create an [`Auth`] layer for the provided _username_.
    ///
    /// # Note
    /// The layer always starts with the `none` authentication method
    /// to discover the methods available on the server.
    ///
    /// Also while the `publickey` method allows for multiple tries,
    /// the `password` method will only keep the last one provided to [`Self::password`].
    pub fn new(username: impl Into<String>, service: R) -> Self {
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
            .extract_if(|m| continue_with.into_iter().any(|method| m.as_ref() == method))
            .next()
    }

    async fn attempt_method(&mut self, method: Method) -> Result<()> {
        // TODO: Implement methods
        match method {
            Method::None => todo!(),
            Method::Publickey { key } => todo!(),
            Method::Password { password } => todo!(),
        }

        Ok(())
    }
}

impl<R: Request> Request for Auth<R> {
    const SERVICE_NAME: &'static str = crate::SERVICE_NAME;

    async fn proceed(
        &mut self,
        session: &mut Session<impl AsyncBufRead + AsyncWrite + Unpin + Send, impl Side>,
    ) -> Result<()> {
        self.attempt_method(Method::None).await?;

        loop {
            let response = session.recv().await?;

            if response.to::<userauth::Success>().is_ok() {
                break self.service.proceed(session).await;
            } else if let Ok(userauth::Failure { continue_with, .. }) = response.to() {
                // TODO: Take care of partial success

                if let Some(method) = self.next_method(&continue_with) {
                    self.attempt_method(method).await?;
                } else {
                    session
                        .disconnect(
                            DisconnectReason::NoMoreAuthMethodsAvailable,
                            "Exhausted available authentication methods.",
                        )
                        .await?;
                };
            } else {
                // TODO: Take care of special messages (AuthChangePasswdReq, etc.)

                session
                    .disconnect(
                        DisconnectReason::ProtocolError,
                        format!(
                            "Unexpected message in the context of the `{}` service.",
                            Self::SERVICE_NAME
                        ),
                    )
                    .await?;
            }
        }
    }
}
