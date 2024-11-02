use enumset::EnumSetType;
use ssh_packet::{arch::Ascii, userauth};

/// Possible authentication methods in the SSH protocol.
#[derive(Debug, EnumSetType)]
pub enum Method {
    /// The SSH `none` authentication method.
    None,

    /// The SSH `publickey` authentication method.
    Publickey,

    /// The SSH `password` authentication method.
    Password,

    /// The SSH `hostbased` authentication method.
    Hostbased,

    /// The SSH `keyboard-interactive` authentication method.
    KeyboardInteractive,
}

impl Method {
    pub fn to_ascii(self) -> Ascii<'static> {
        match self {
            Self::None => userauth::Method::NONE,
            Self::Publickey => userauth::Method::PUBLICKEY,
            Self::Password => userauth::Method::PASSWORD,
            Self::Hostbased => userauth::Method::HOSTBASED,
            Self::KeyboardInteractive => userauth::Method::KEYBOARD_INTERACTIVE,
        }
    }
}

impl AsRef<Method> for userauth::Method<'_> {
    fn as_ref(&self) -> &Method {
        match self {
            userauth::Method::None => &Method::None,
            userauth::Method::Publickey { .. } => &Method::Publickey,
            userauth::Method::Password { .. } => &Method::Password,
            userauth::Method::Hostbased { .. } => &Method::Hostbased,
            userauth::Method::KeyboardInteractive { .. } => &Method::KeyboardInteractive,
        }
    }
}
