use ssh_key::PrivateKey;

/// Possible authentication methods in the SSH protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum Method {
    /// The SSH `none` authentication method.
    None,

    /// The SSH `publickey` authentication method.
    Publickey { key: Box<PrivateKey> },

    /// The SSH `password` authentication method.
    Password { password: String },
}

impl std::hash::Hash for Method {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);

        // Allow keys with different fingerprints to exist alongside
        if let Self::Publickey { key } = self {
            key.fingerprint(ssh_key::HashAlg::Sha256)
                .as_bytes()
                .hash(state);
        }
    }
}
