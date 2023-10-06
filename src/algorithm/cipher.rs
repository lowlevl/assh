use aes_gcm::Tag;
use strum::{EnumString, EnumVariantNames};

use crate::{Error, Result};

fn init<T: cipher::KeyIvInit>(key: &[u8], iv: &[u8]) -> Box<T> {
    T::new_from_slices(key, iv)
        .expect("Key derivation failed")
        .into()
}

pub trait Cipher {
    fn block_size(&self) -> usize;
    fn key_size(&self) -> usize;
    fn iv_size(&self) -> usize;

    fn has_tag(&self) -> bool;
    fn is_some(&self) -> bool;
}

#[derive(Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum EncryptorCipher {
    // /// ChaCha20-Poly1305.
    // #[strum(serialize = "chacha20-poly1305@openssh.com")]
    // ChaCha20Poly1305,

    // /// AES-256 in Galois/Counter Mode (GCM).
    // #[strum(serialize = "aes256-gcm@openssh.com")]
    // Aes256Gcm,

    // /// AES-128 in Galois/Counter Mode (GCM).
    // #[strum(serialize = "aes128-gcm@openssh.com")]
    // Aes128Gcm,
    //
    /// AES-256 in counter (CTR) mode.
    Aes256Ctr(Option<Box<ctr::Ctr128BE<aes::Aes256>>>),

    /// AES-192 in counter (CTR) mode.
    Aes192Ctr(Option<Box<ctr::Ctr128BE<aes::Aes192>>>),

    /// AES-128 in counter (CTR) mode.
    Aes128Ctr(Option<Box<ctr::Ctr128BE<aes::Aes128>>>),

    /// AES-256 in cipher block chaining (CBC) mode.
    Aes256Cbc(Option<Box<cbc::Encryptor<aes::Aes256>>>),

    /// AES-192 in cipher block chaining (CBC) mode.
    Aes192Cbc(Option<Box<cbc::Encryptor<aes::Aes192>>>),

    /// AES-128 in cipher block chaining (CBC) mode.
    Aes128Cbc(Option<Box<cbc::Encryptor<aes::Aes128>>>),

    /// TripleDES in block chaining (CBC) mode.
    #[strum(serialize = "3des-cbc")]
    TDesCbc(Option<Box<cbc::Encryptor<des::TdesEde3>>>),

    /// No cipher.
    #[default]
    None,
}

impl std::fmt::Debug for EncryptorCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256Ctr(_) => f.debug_tuple("Aes256Ctr").finish(),
            Self::Aes192Ctr(_) => f.debug_tuple("Aes192Ctr").finish(),
            Self::Aes128Ctr(_) => f.debug_tuple("Aes128Ctr").finish(),
            Self::Aes256Cbc(_) => f.debug_tuple("Aes256Cbc").finish(),
            Self::Aes192Cbc(_) => f.debug_tuple("Aes192Cbc").finish(),
            Self::Aes128Cbc(_) => f.debug_tuple("Aes128Cbc").finish(),
            Self::TDesCbc(_) => f.debug_tuple("TDesCbc").finish(),
            Self::None => write!(f, "None"),
        }
    }
}

impl EncryptorCipher {
    fn ctr<C: ctr::cipher::StreamCipher>(cipher: &mut C, buffer: &mut [u8]) -> Result<Option<Tag>> {
        cipher
            .try_apply_keystream(buffer)
            .map_err(|_| Error::Cipher)?;

        Ok(None)
    }

    fn cbc<C: cbc::cipher::BlockEncryptMut>(
        cipher: &mut C,
        buffer: &mut [u8],
    ) -> Result<Option<Tag>> {
        use cbc::cipher::inout;

        let data = inout::InOutBufReserved::from_mut_slice(buffer, buffer.len())
            .map_err(|_| Error::Cipher)?;

        let mut buf = data
            .into_padded_blocks::<cbc::cipher::block_padding::NoPadding, C::BlockSize>()
            .map_err(|_| Error::Cipher)?;

        cipher.encrypt_blocks_inout_mut(buf.get_blocks());
        if let Some(block) = buf.get_tail_block() {
            cipher.encrypt_block_inout_mut(block);
        }

        Ok(None)
    }

    pub(crate) fn encrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<Option<Tag>> {
        match self {
            Self::Aes256Ctr(cipher) => {
                Self::ctr(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes192Ctr(cipher) => {
                Self::ctr(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes128Ctr(cipher) => {
                Self::ctr(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes256Cbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes192Cbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes128Cbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::TDesCbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::None => Ok(None),
        }
    }
}

impl Cipher for EncryptorCipher {
    fn block_size(&self) -> usize {
        match self {
            Self::None | Self::TDesCbc { .. } => 8,
            Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => 16,
        }
    }

    fn key_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::TDesCbc { .. } => 24,
            Self::Aes128Cbc { .. } => 16,
            Self::Aes192Cbc { .. } => 24,
            Self::Aes256Cbc { .. } => 32,
            Self::Aes128Ctr { .. } => 16,
            Self::Aes192Ctr { .. } => 24,
            Self::Aes256Ctr { .. } => 32,
        }
    }

    fn iv_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::TDesCbc { .. } => 8,
            Self::Aes128Cbc { .. } => 16,
            Self::Aes192Cbc { .. } => 16,
            Self::Aes256Cbc { .. } => 16,
            Self::Aes128Ctr { .. } => 16,
            Self::Aes192Ctr { .. } => 16,
            Self::Aes256Ctr { .. } => 16,
        }
    }

    fn has_tag(&self) -> bool {
        match self {
            Self::None
            | Self::TDesCbc { .. }
            | Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => false,
        }
    }

    fn is_some(&self) -> bool {
        match self {
            Self::None => false,
            Self::TDesCbc { .. }
            | Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => true,
        }
    }
}

#[derive(Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum DecryptorCipher {
    // /// ChaCha20-Poly1305.
    // #[strum(serialize = "chacha20-poly1305@openssh.com")]
    // ChaCha20Poly1305,

    // /// AES-256 in Galois/Counter Mode (GCM).
    // #[strum(serialize = "aes256-gcm@openssh.com")]
    // Aes256Gcm,

    // /// AES-128 in Galois/Counter Mode (GCM).
    // #[strum(serialize = "aes128-gcm@openssh.com")]
    // Aes128Gcm,
    //
    /// AES-256 in counter (CTR) mode.
    Aes256Ctr(Option<Box<ctr::Ctr128BE<aes::Aes256>>>),

    /// AES-192 in counter (CTR) mode.
    Aes192Ctr(Option<Box<ctr::Ctr128BE<aes::Aes192>>>),

    /// AES-128 in counter (CTR) mode.
    Aes128Ctr(Option<Box<ctr::Ctr128BE<aes::Aes128>>>),

    /// AES-256 in cipher block chaining (CBC) mode.
    Aes256Cbc(Option<Box<cbc::Decryptor<aes::Aes256>>>),

    /// AES-192 in cipher block chaining (CBC) mode.
    Aes192Cbc(Option<Box<cbc::Decryptor<aes::Aes192>>>),

    /// AES-128 in cipher block chaining (CBC) mode.
    Aes128Cbc(Option<Box<cbc::Decryptor<aes::Aes128>>>),

    /// TripleDES in block chaining (CBC) mode.
    #[strum(serialize = "3des-cbc")]
    TDesCbc(Option<Box<cbc::Decryptor<des::TdesEde3>>>),

    /// No cipher.
    #[default]
    None,
}

impl std::fmt::Debug for DecryptorCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256Ctr(_) => f.debug_tuple("Aes256Ctr").finish(),
            Self::Aes192Ctr(_) => f.debug_tuple("Aes192Ctr").finish(),
            Self::Aes128Ctr(_) => f.debug_tuple("Aes128Ctr").finish(),
            Self::Aes256Cbc(_) => f.debug_tuple("Aes256Cbc").finish(),
            Self::Aes192Cbc(_) => f.debug_tuple("Aes192Cbc").finish(),
            Self::Aes128Cbc(_) => f.debug_tuple("Aes128Cbc").finish(),
            Self::TDesCbc(_) => f.debug_tuple("TDesCbc").finish(),
            Self::None => write!(f, "None"),
        }
    }
}

impl DecryptorCipher {
    fn cbc<C: cbc::cipher::BlockDecryptMut>(
        cipher: &mut C,
        buffer: &mut [u8],
    ) -> Result<Option<Tag>> {
        use cbc::cipher::inout;

        let data = inout::InOutBufReserved::from_mut_slice(buffer, buffer.len())
            .map_err(|_| Error::Cipher)?;

        let mut buf = data
            .into_padded_blocks::<cbc::cipher::block_padding::NoPadding, C::BlockSize>()
            .map_err(|_| Error::Cipher)?;

        cipher.decrypt_blocks_inout_mut(buf.get_blocks());
        if let Some(block) = buf.get_tail_block() {
            cipher.decrypt_block_inout_mut(block);
        }

        Ok(None)
    }

    pub(crate) fn decrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<Option<Tag>> {
        match self {
            // In CTR mode, encryption and decrytion is the same
            Self::Aes256Ctr(cipher) => {
                EncryptorCipher::ctr(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes192Ctr(cipher) => {
                EncryptorCipher::ctr(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes128Ctr(cipher) => {
                EncryptorCipher::ctr(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes256Cbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes192Cbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::Aes128Cbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::TDesCbc(cipher) => {
                Self::cbc(cipher.get_or_insert_with(|| init(key, iv)).as_mut(), buffer)
            }
            Self::None => Ok(None),
        }
    }
}

impl Cipher for DecryptorCipher {
    fn block_size(&self) -> usize {
        match self {
            Self::None | Self::TDesCbc { .. } => 8,
            Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => 16,
        }
    }

    fn key_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::TDesCbc { .. } => 24,
            Self::Aes128Cbc { .. } => 16,
            Self::Aes192Cbc { .. } => 24,
            Self::Aes256Cbc { .. } => 32,
            Self::Aes128Ctr { .. } => 16,
            Self::Aes192Ctr { .. } => 24,
            Self::Aes256Ctr { .. } => 32,
        }
    }

    fn iv_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::TDesCbc { .. } => 8,
            Self::Aes128Cbc { .. } => 16,
            Self::Aes192Cbc { .. } => 16,
            Self::Aes256Cbc { .. } => 16,
            Self::Aes128Ctr { .. } => 16,
            Self::Aes192Ctr { .. } => 16,
            Self::Aes256Ctr { .. } => 16,
        }
    }

    fn has_tag(&self) -> bool {
        match self {
            Self::None
            | Self::TDesCbc { .. }
            | Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => false,
        }
    }

    fn is_some(&self) -> bool {
        match self {
            Self::None => false,
            Self::TDesCbc { .. }
            | Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => true,
        }
    }
}
