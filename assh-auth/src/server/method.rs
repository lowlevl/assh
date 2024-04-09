use enumset::EnumSetType;
use ssh_packet::userauth;

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

impl AsRef<str> for Method {
    fn as_ref(&self) -> &str {
        match self {
            Self::None => userauth::Method::NONE,
            Self::Publickey => userauth::Method::PUBLICKEY,
            Self::Password => userauth::Method::PASSWORD,
            Self::Hostbased => userauth::Method::HOSTBASED,
            Self::KeyboardInteractive => userauth::Method::KEYBOARD_INTERACTIVE,
        }
    }
}

impl From<&userauth::Method> for Method {
    fn from(value: &userauth::Method) -> Self {
        match value {
            userauth::Method::None => Self::None,
            userauth::Method::Publickey { .. } => Self::Publickey,
            userauth::Method::Password { .. } => Self::Password,
            userauth::Method::Hostbased { .. } => Self::Hostbased,
            userauth::Method::KeyboardInteractive { .. } => Self::KeyboardInteractive,
        }
    }
}
