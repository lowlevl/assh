use cipher::KeyIvInit;
use digest::{Digest, FixedOutputReset};
use ssh_packet::{arch::NameList, trans::KexInit};
use strum::{AsRefStr, EnumString};

use crate::{
    Error, Result,
    side::{client::Client, server::Server},
};

impl super::Negociate<Client> for Cipher {
    const ERR: Error = Error::NoCommonCipher;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.encryption_algorithms_client_to_server
    }
}

impl super::Negociate<Server> for Cipher {
    const ERR: Error = Error::NoCommonCipher;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.encryption_algorithms_server_to_client
    }
}

// TODO: (feature) Implement the latest and safest ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`).

/// SSH cipher algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, EnumString, AsRefStr)]
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
    None,
}

fn ctr<C: ctr::cipher::StreamCipher>(state: &mut C, buffer: &mut [u8]) -> Result<()> {
    state
        .try_apply_keystream(buffer)
        .map_err(|_| Error::Cipher)?;

    Ok(())
}

#[derive(Debug, Default)]
pub enum EncState {
    Aes256Ctr(ctr::Ctr128BE<aes::Aes256>),
    Aes192Ctr(ctr::Ctr128BE<aes::Aes192>),
    Aes128Ctr(ctr::Ctr128BE<aes::Aes128>),
    Aes256Cbc(cbc::Encryptor<aes::Aes256>),
    Aes192Cbc(cbc::Encryptor<aes::Aes192>),
    Aes128Cbc(cbc::Encryptor<aes::Aes128>),
    TDesCbc(cbc::Encryptor<des::TdesEde3>),
    #[default]
    None,
}

impl EncState {
    pub fn new<const IV: u8, const K: u8, H: Digest + FixedOutputReset>(
        cipher: &Cipher,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        match cipher {
            Cipher::Aes256Ctr => Self::Aes256Ctr(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes192Ctr => Self::Aes192Ctr(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes128Ctr => Self::Aes128Ctr(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes256Cbc => Self::Aes256Cbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes192Cbc => Self::Aes192Cbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes128Cbc => Self::Aes128Cbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::TDesCbc => Self::TDesCbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::None => Self::None,
        }
    }

    fn cbc<C: cbc::cipher::BlockModeEncrypt>(state: &mut C, buffer: &mut [u8]) -> Result<()> {
        use cbc::cipher::inout;

        let data = inout::InOutBufReserved::from_mut_slice(buffer, buffer.len())
            .map_err(|_| Error::Cipher)?;

        let mut buf = data
            .into_padded_blocks::<cbc::cipher::block_padding::NoPadding, C::BlockSize>()
            .map_err(|_| Error::Cipher)?;

        state.encrypt_blocks_inout(buf.get_blocks());
        if let Some(block) = buf.get_tail_block() {
            state.encrypt_block_inout(block);
        }

        Ok(())
    }

    pub fn encrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        match self {
            Self::Aes256Ctr(state) => ctr(state, buffer),
            Self::Aes192Ctr(state) => ctr(state, buffer),
            Self::Aes128Ctr(state) => ctr(state, buffer),
            Self::Aes256Cbc(state) => Self::cbc(state, buffer),
            Self::Aes192Cbc(state) => Self::cbc(state, buffer),
            Self::Aes128Cbc(state) => Self::cbc(state, buffer),
            Self::TDesCbc(state) => Self::cbc(state, buffer),
            Self::None => Ok(()),
        }
    }

    pub fn block_size(&self) -> usize {
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
}

#[derive(Debug, Default)]
pub enum DecState {
    Aes256Ctr(ctr::Ctr128BE<aes::Aes256>),
    Aes192Ctr(ctr::Ctr128BE<aes::Aes192>),
    Aes128Ctr(ctr::Ctr128BE<aes::Aes128>),
    Aes256Cbc(cbc::Decryptor<aes::Aes256>),
    Aes192Cbc(cbc::Decryptor<aes::Aes192>),
    Aes128Cbc(cbc::Decryptor<aes::Aes128>),
    TDesCbc(cbc::Decryptor<des::TdesEde3>),
    #[default]
    None,
}

impl DecState {
    pub fn new<const IV: u8, const K: u8, H: Digest + FixedOutputReset>(
        cipher: &Cipher,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        match cipher {
            Cipher::Aes256Ctr => Self::Aes256Ctr(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes192Ctr => Self::Aes192Ctr(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes128Ctr => Self::Aes128Ctr(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes256Cbc => Self::Aes256Cbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes192Cbc => Self::Aes192Cbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::Aes128Cbc => Self::Aes128Cbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::TDesCbc => Self::TDesCbc(KeyIvInit::new(
                &super::kdf::<_, H>(K, secret, hash, session_id).into(),
                &super::kdf::<_, H>(IV, secret, hash, session_id).into(),
            )),
            Cipher::None => Self::None,
        }
    }

    fn cbc<C: cbc::cipher::BlockModeDecrypt>(cipher: &mut C, buffer: &mut [u8]) -> Result<()> {
        use cbc::cipher::inout;

        let data = inout::InOutBufReserved::from_mut_slice(buffer, buffer.len())
            .map_err(|_| Error::Cipher)?;

        let mut buf = data
            .into_padded_blocks::<cbc::cipher::block_padding::NoPadding, C::BlockSize>()
            .map_err(|_| Error::Cipher)?;

        cipher.decrypt_blocks_inout(buf.get_blocks());
        if let Some(block) = buf.get_tail_block() {
            cipher.decrypt_block_inout(block);
        }

        Ok(())
    }

    pub fn decrypt(&mut self, buffer: &mut [u8]) -> Result<()> {
        match self {
            Self::Aes256Ctr(state) => ctr(state, buffer),
            Self::Aes192Ctr(state) => ctr(state, buffer),
            Self::Aes128Ctr(state) => ctr(state, buffer),
            Self::Aes256Cbc(state) => Self::cbc(state, buffer),
            Self::Aes192Cbc(state) => Self::cbc(state, buffer),
            Self::Aes128Cbc(state) => Self::cbc(state, buffer),
            Self::TDesCbc(state) => Self::cbc(state, buffer),
            Self::None => Ok(()),
        }
    }

    pub fn block_size(&self) -> usize {
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
}
