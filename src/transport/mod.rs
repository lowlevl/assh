use rand::Rng;
use ssh_key::{Algorithm, Cipher};
use ssh_packet::{trans::KexInit, OpeningCipher, SealingCipher};

mod compress;
pub use compress::CompressAlg;

mod encrypt;
pub use encrypt::EncryptAlg;

mod hmac;
pub use hmac::HmacAlg;

mod kex;
pub use kex::KexAlg;

mod keychain;
pub use keychain::KeyChain;

use crate::{Error, Result};

#[derive(Debug, Default)]
pub struct TransportPair {
    pub rchain: KeyChain,
    pub ralg: Transport,
    pub tchain: KeyChain,
    pub talg: Transport,
}

#[derive(Debug)]
pub struct Transport {
    pub encrypt: Cipher,
    pub hmac: hmac::HmacAlg,
    pub compress: compress::CompressAlg,
    pub seq: u32,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            encrypt: Cipher::None,
            hmac: Default::default(),
            compress: Default::default(),
            seq: 0,
        }
    }
}

impl Transport {
    pub const MIN_PACKET_SIZE: usize = 16;
    pub const MIN_PAD_SIZE: usize = 4;
    pub const MIN_ALIGN: usize = 8;

    pub fn padding(&self, payload: usize) -> u8 {
        let align = self.encrypt.block_size().max(Self::MIN_ALIGN);

        let size = if self.encrypt.is_some() && !self.encrypt.has_tag() {
            std::mem::size_of::<u8>() + payload
        } else {
            std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + payload
        };
        let padding = align - size % align;

        let padding = if padding < Self::MIN_PAD_SIZE {
            padding + align
        } else {
            padding
        };

        if size + padding < self.encrypt.block_size().max(Self::MIN_PACKET_SIZE) {
            (padding + align) as u8
        } else {
            padding as u8
        }
    }

    pub fn negociate(
        clientkex: &KexInit,
        serverkex: &KexInit,
    ) -> Result<(KexAlg, Algorithm, Self, Self)> {
        let client_to_server = Self {
            encrypt: clientkex
                .encryption_algorithms_client_to_server
                .preferred_in(&serverkex.encryption_algorithms_client_to_server)
                .ok_or(Error::NoCommonEncryption)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            hmac: clientkex
                .mac_algorithms_client_to_server
                .preferred_in(&serverkex.mac_algorithms_client_to_server)
                .ok_or(Error::NoCommonHmac)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            compress: clientkex
                .compression_algorithms_client_to_server
                .preferred_in(&serverkex.compression_algorithms_client_to_server)
                .ok_or(Error::NoCommonCompression)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            seq: 0,
        };
        let server_to_client = Self {
            encrypt: clientkex
                .encryption_algorithms_server_to_client
                .preferred_in(&serverkex.encryption_algorithms_server_to_client)
                .ok_or(Error::NoCommonEncryption)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            hmac: clientkex
                .mac_algorithms_server_to_client
                .preferred_in(&serverkex.mac_algorithms_server_to_client)
                .ok_or(Error::NoCommonHmac)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            compress: clientkex
                .compression_algorithms_server_to_client
                .preferred_in(&serverkex.compression_algorithms_server_to_client)
                .ok_or(Error::NoCommonCompression)?
                .parse()
                .map_err(|_| Error::UnsupportedAlgorithm)?,
            seq: 0,
        };
        let kexalg: KexAlg = clientkex
            .kex_algorithms
            .preferred_in(&serverkex.kex_algorithms)
            .ok_or(Error::NoCommonKex)?
            .parse()
            .map_err(|_| Error::UnsupportedAlgorithm)?;
        let keyalg: Algorithm = clientkex
            .server_host_key_algorithms
            .preferred_in(&serverkex.server_host_key_algorithms)
            .ok_or(Error::NoCommonKey)?
            .parse()
            .map_err(|_| Error::UnsupportedAlgorithm)?;

        Ok((kexalg, keyalg, client_to_server, server_to_client))
    }
}

impl OpeningCipher for TransportPair {
    type Err = Error;

    fn mac(&self) -> usize {
        if self.ralg.encrypt.has_tag() {
            // If the encryption algorithm has a Tag,
            // the MAC is included in the payload.
            0
        } else {
            self.ralg.hmac.size()
        }
    }

    fn verify<B: AsRef<[u8]>>(&mut self, blob: B, mac: Vec<u8>) -> Result<(), Self::Err> {
        Ok(())
    }

    fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<B, Self::Err> {
        if self.ralg.encrypt.is_some() {
            self.ralg
                .encrypt
                .decrypt(&self.rchain.key, &self.rchain.iv, buf.as_mut(), None)?;
        }

        Ok(buf)
    }

    fn decompress<B: AsRef<[u8]>>(&mut self, blob: B) -> Result<Vec<u8>, Self::Err> {
        Ok(blob.as_ref().to_vec())
    }
}

impl SealingCipher for TransportPair {
    type Err = Error;

    fn mac(&self) -> usize {
        if self.talg.encrypt.has_tag() {
            // If the encryption algorithm has a Tag,
            // the MAC is included in the payload.
            0
        } else {
            self.talg.hmac.size()
        }
    }

    fn compress<B: AsRef<[u8]>>(&mut self, blob: B) -> Result<Vec<u8>, Self::Err> {
        Ok(blob.as_ref().to_vec())
    }

    fn pad(&mut self, blob: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        let padding = self.talg.padding(blob.len());
        let mut rng = rand::thread_rng();

        // prefix with the size
        let mut new = vec![padding];
        new.extend_from_slice(&blob);

        // fill with random
        new.resize_with(new.len() + padding as usize, || rng.gen());

        Ok(new)
    }

    fn encrypt<B: AsMut<[u8]>>(&mut self, mut blob: B) -> Result<B, Self::Err> {
        if self.talg.encrypt.is_some() {
            self.talg
                .encrypt
                .encrypt(&self.tchain.key, &self.tchain.iv, blob.as_mut())?;
        }

        Ok(blob)
    }

    fn sign(&mut self, mut blob: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        blob.resize(blob.len() + SealingCipher::mac(self), 0);

        Ok(blob)
    }
}
