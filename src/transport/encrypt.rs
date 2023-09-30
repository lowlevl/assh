use ssh_key::Cipher;
use strum::{EnumString, EnumVariantNames};

#[derive(Debug)]
pub struct EncryptPair {
    pub rx: Cipher,
    pub tx: Cipher,
}

impl Default for EncryptPair {
    fn default() -> Self {
        Self {
            rx: Cipher::None,
            tx: Cipher::None,
        }
    }
}

#[derive(Debug, Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum EncryptAlg {
    /// ChaCha20-Poly1305.
    #[strum(serialize = "chacha20-poly1305@openssh.com")]
    ChaCha20Poly1305,

    /// AES-256 in Galois/Counter Mode (GCM).
    #[strum(serialize = "aes256-gcm@openssh.com")]
    Aes256Gcm,

    /// AES-128 in Galois/Counter Mode (GCM).
    #[strum(serialize = "aes128-gcm@openssh.com")]
    Aes128Gcm,

    /// AES-256 in counter (CTR) mode.
    Aes256Ctr,

    /// AES-192 in counter (CTR) mode.
    Aes192Ctr,

    /// AES-128 in counter (CTR) mode.
    Aes128Ctr,

    /// AES-256 in cipher block chaining (CBC) mode.
    Aes256Cbc,

    /// AES-192 in cipher block chaining (CBC) mode.
    Aes192Cbc,

    /// AES-128 in cipher block chaining (CBC) mode.
    Aes128Cbc,

    /// TripleDES in block chaining (CBC) mode.
    #[strum(serialize = "3des-cbc")]
    TDesCbc,

    /// No cipher.
    #[default]
    None,
}
