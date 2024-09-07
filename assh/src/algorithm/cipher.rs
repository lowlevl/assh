use aes_gcm::Tag;
use ssh_packet::trans::KexInit;
use strum::{AsRefStr, EnumString};

use crate::{Error, Result};

// TODO: (optimization) Get rid of this Box<dyn> altogether.
pub type CipherState = Box<dyn std::any::Any + Send + Sync>;

pub fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<(Cipher, Cipher)> {
    Ok((
        clientkex
            .encryption_algorithms_client_to_server
            .preferred_in(&serverkex.encryption_algorithms_client_to_server)
            .ok_or(Error::NoCommonCipher)?
            .parse()
            .map_err(|_| Error::NoCommonCipher)?,
        clientkex
            .encryption_algorithms_server_to_client
            .preferred_in(&serverkex.encryption_algorithms_server_to_client)
            .ok_or(Error::NoCommonCipher)?
            .parse()
            .map_err(|_| Error::NoCommonCipher)?,
    ))
}

// TODO: (feature) Implement the latest and safest ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`).

/// SSH cipher algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, EnumString, AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub enum Cipher {
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

    /// TripleDES in cipher block chaining (CBC) mode.
    #[strum(serialize = "3des-cbc")]
    TDesCbc,

    /// No cipher algorithm.
    #[default]
    None,
}

impl Cipher {
    /// This method is a hack to solve deduplication of the enum
    /// variants and to store the cipher states inside a dynamically
    /// typed `Box<dyn std::any::Any>`.
    fn state<'s, T: cipher::KeyIvInit + Send + Sync + 'static>(
        state: &'s mut Option<CipherState>,
        key: &[u8],
        iv: &[u8],
    ) -> &'s mut T {
        state
            .get_or_insert_with(|| {
                Box::new(T::new_from_slices(key, iv).expect("Key derivation failed horribly"))
            })
            .downcast_mut()
            .expect("State changed in the meanwhile")
    }

    fn ctr<C: ctr::cipher::StreamCipher>(cipher: &mut C, buffer: &mut [u8]) -> Result<Option<Tag>> {
        cipher
            .try_apply_keystream(buffer)
            .map_err(|_| Error::Cipher)?;

        Ok(None)
    }

    pub(crate) fn encrypt(
        &mut self,
        state: &mut Option<CipherState>,
        key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<Option<Tag>> {
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

        match self {
            Self::Aes256Ctr => Self::ctr(
                Self::state::<ctr::Ctr128BE<aes::Aes256>>(state, key, iv),
                buffer,
            ),
            Self::Aes192Ctr => Self::ctr(
                Self::state::<ctr::Ctr128BE<aes::Aes192>>(state, key, iv),
                buffer,
            ),
            Self::Aes128Ctr => Self::ctr(
                Self::state::<ctr::Ctr128BE<aes::Aes128>>(state, key, iv),
                buffer,
            ),
            Self::Aes256Cbc => cbc(
                Self::state::<cbc::Encryptor<aes::Aes256>>(state, key, iv),
                buffer,
            ),
            Self::Aes192Cbc => cbc(
                Self::state::<cbc::Encryptor<aes::Aes192>>(state, key, iv),
                buffer,
            ),
            Self::Aes128Cbc => cbc(
                Self::state::<cbc::Encryptor<aes::Aes128>>(state, key, iv),
                buffer,
            ),
            Self::TDesCbc => cbc(
                Self::state::<cbc::Encryptor<des::TdesEde3>>(state, key, iv),
                buffer,
            ),
            Self::None => Ok(None),
        }
    }

    pub(crate) fn decrypt(
        &mut self,
        state: &mut Option<CipherState>,
        key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<Option<Tag>> {
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

        match self {
            // In CTR mode, encryption and decrytion are the same
            Self::Aes256Ctr | Self::Aes192Ctr | Self::Aes128Ctr => {
                self.encrypt(state, key, iv, buffer)
            }
            Self::Aes256Cbc => cbc(
                Self::state::<cbc::Decryptor<aes::Aes256>>(state, key, iv),
                buffer,
            ),
            Self::Aes192Cbc => cbc(
                Self::state::<cbc::Decryptor<aes::Aes192>>(state, key, iv),
                buffer,
            ),
            Self::Aes128Cbc => cbc(
                Self::state::<cbc::Decryptor<aes::Aes128>>(state, key, iv),
                buffer,
            ),
            Self::TDesCbc => cbc(
                Self::state::<cbc::Decryptor<des::TdesEde3>>(state, key, iv),
                buffer,
            ),
            Self::None => Ok(None),
        }
    }

    pub(crate) fn block_size(&self) -> usize {
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

    pub(crate) fn key_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Cbc { .. } | Self::Aes128Ctr { .. } => 16,
            Self::TDesCbc { .. } | Self::Aes192Cbc { .. } | Self::Aes192Ctr { .. } => 24,
            Self::Aes256Cbc { .. } | Self::Aes256Ctr { .. } => 32,
        }
    }

    pub(crate) fn iv_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::TDesCbc { .. } => 8,
            Self::Aes128Cbc { .. }
            | Self::Aes192Cbc { .. }
            | Self::Aes256Cbc { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => 16,
        }
    }

    // pub(crate) fn has_tag(&self) -> bool {
    //     match self {
    //         Self::None
    //         | Self::TDesCbc { .. }
    //         | Self::Aes128Cbc { .. }
    //         | Self::Aes192Cbc { .. }
    //         | Self::Aes256Cbc { .. }
    //         | Self::Aes128Ctr { .. }
    //         | Self::Aes192Ctr { .. }
    //         | Self::Aes256Ctr { .. } => false,
    //     }
    // }
}
