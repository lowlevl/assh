use rand::RngCore;
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

    fn mac_len(&self) -> usize {
        if self.ralg.encrypt.has_tag() {
            // If the encryption algorithm has a Tag,
            // the MAC is included in the payload.
            0
        } else {
            self.ralg.hmac.size()
        }
    }

    fn decrypt<'b, B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<B, Self::Err> {
        // TODO: Decompression
        if self.ralg.encrypt.is_some() {
            tracing::trace!("decrypting: {:?}", buf.as_mut());
            self.ralg
                .encrypt
                .decrypt(&self.rchain.key, &self.rchain.iv, buf.as_mut(), None)?;
        }

        Ok(buf)
    }

    fn open(&mut self, packet: ssh_packet::Packet) -> Result<Vec<u8>, Self::Err> {
        // TODO: Verify padding
        // TODO: Verify MAC

        Ok(packet.payload)
    }
}

impl SealingCipher for TransportPair {
    type Err = Error;

    fn mac_len(&self) -> usize {
        if self.talg.encrypt.has_tag() {
            // If the encryption algorithm has a Tag,
            // the MAC is included in the payload.
            0
        } else {
            self.talg.hmac.size()
        }
    }

    fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<B, Self::Err> {
        // TODO: Compression
        if self.talg.encrypt.is_some() {
            self.talg
                .encrypt
                .encrypt(&self.tchain.key, &self.tchain.iv, buf.as_mut())?;
        }

        Ok(buf)
    }

    fn seal(&mut self, payload: Vec<u8>) -> Result<Packet, Self::Err> {
        let mut padding = vec![0u8; self.talg.padding(payload.len())];
        rand::thread_rng().fill_bytes(&mut padding);

        let mac = Default::default();

        Ok(Packet {
            payload,
            padding,
            mac,
        })
    }
}
