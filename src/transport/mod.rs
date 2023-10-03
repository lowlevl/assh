use ring::rand::SecureRandom;
use ssh_key::{Algorithm, Cipher};
use ssh_packet::{trans::KexInit, OpeningCipher, Packet, SealingCipher};

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

    pub fn padding(&self, payload: usize) -> usize {
        let align = self.encrypt.block_size().max(Self::MIN_ALIGN);

        let size = std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + payload;
        let padding = align - size % align;

        let padding = if padding < Self::MIN_PAD_SIZE {
            padding + align
        } else {
            padding
        };

        if size + padding < self.encrypt.block_size().max(Self::MIN_PACKET_SIZE) {
            padding + align
        } else {
            padding
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

    fn size(&self) -> usize {
        if self.ralg.encrypt.has_tag() {
            // std::mem::size_of::<ssh_cipher::Tag>()
            0
        } else {
            self.ralg.hmac.size()
        }
    }

    fn open(&mut self, packet: ssh_packet::Packet) -> Result<Vec<u8>, Self::Err> {
        // TODO: Verify padding

        let mut payload = self.ralg.compress.decompress(packet.payload);

        if self.ralg.encrypt.is_some() {
            // let tag = self
            //     .ralg
            //     .encrypt
            //     .has_tag()
            //     .then(|| packet.mac.try_into())
            //     .transpose()
            //     .map_err(|_| ssh_key::Error::Crypto)?;

            self.ralg
                .encrypt
                .decrypt(&self.rchain.key, &self.rchain.iv, &mut payload, None)?;

            // if tag.is_none() && !self.ralg.hmac.verify(&packet) {
            //     return Err(ssh_key::Error::Crypto.into());
            // }
        }

        Ok(payload)
    }
}

impl SealingCipher for TransportPair {
    type Err = Error;

    fn seal(&mut self, mut payload: Vec<u8>) -> Result<Packet, Self::Err> {
        let mut tag = None;
        if self.talg.encrypt.is_some() {
            tag = self
                .talg
                .encrypt
                .encrypt(&self.rchain.key, &self.tchain.iv, &mut payload)?;
        }

        let payload = self.talg.compress.compress(payload);
        let mut padding = vec![0u8; self.talg.padding(payload.len())];
        ring::rand::SystemRandom::new().fill(&mut padding[..])?;

        let mac = tag
            .map(Into::into)
            .unwrap_or_else(|| self.talg.hmac.sign(&payload));

        Ok(Packet {
            payload,
            padding,
            mac,
        })
    }
}
