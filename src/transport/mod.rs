use rand::Rng;
use ssh_packet::{OpeningCipher, SealingCipher};

mod keychain;
pub use keychain::KeyChain;

use crate::{
    algorithm::{self, Cipher},
    Error, Result,
};

#[derive(Debug, Default)]
pub struct TransportPair {
    pub rchain: KeyChain,
    pub ralg: Transport<algorithm::DecryptorCipher>,
    pub rseq: u32,

    pub tchain: KeyChain,
    pub talg: Transport<algorithm::EncryptorCipher>,
    pub tseq: u32,
}

#[derive(Debug, Default)]
pub struct Transport<T> {
    pub cipher: T,
    pub hmac: algorithm::Hmac,
    pub compress: algorithm::Compress,
}

impl<T: algorithm::Cipher> Transport<T> {
    pub const MIN_PACKET_SIZE: usize = 16;
    pub const MIN_PAD_SIZE: usize = 4;
    pub const MIN_ALIGN: usize = 8;

    pub fn padding(&self, payload: usize) -> u8 {
        let align = self.cipher.block_size().max(Self::MIN_ALIGN);

        let size = if self.cipher.is_some() && !self.cipher.has_tag() {
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

        if size + padding < self.cipher.block_size().max(Self::MIN_PACKET_SIZE) {
            (padding + align) as u8
        } else {
            padding as u8
        }
    }
}

impl OpeningCipher for TransportPair {
    type Err = Error;

    fn mac(&self) -> usize {
        if self.ralg.cipher.has_tag() {
            // If the encryption algorithm has a Tag,
            // the MAC is included in the payload.
            0
        } else {
            self.ralg.hmac.size()
        }
    }

    fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<B, Self::Err> {
        if self.ralg.cipher.is_some() {
            self.ralg
                .cipher
                .decrypt(&self.rchain.key, &self.rchain.iv, buf.as_mut())?;
        }

        Ok(buf)
    }

    fn open(&mut self, mut buf: Vec<u8>, mac: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        if self.ralg.hmac.etm() {
            self.ralg
                .hmac
                .verify(self.rseq, &buf, &self.rchain.hmac, &mac)?;
            self.decrypt(&mut buf[4..])?;
        } else {
            self.decrypt(&mut buf[4..])?;
            self.ralg
                .hmac
                .verify(self.rseq, &buf, &self.rchain.hmac, &mac)?;
        }

        Ok(buf)
    }

    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        self.ralg.compress.decompress(buf)
    }
}

impl SealingCipher for TransportPair {
    type Err = Error;

    fn mac(&self) -> usize {
        if self.talg.cipher.has_tag() {
            // If the encryption algorithm has a Tag,
            // the MAC is included in the payload.
            0
        } else {
            self.talg.hmac.size()
        }
    }

    fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err> {
        self.talg.compress.compress(buf.as_ref())
    }

    fn pad(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        let padding = self.talg.padding(buf.len());
        let mut rng = rand::thread_rng();

        // prefix with the size
        let mut new = vec![padding];
        new.extend_from_slice(&buf);

        // fill with random
        new.resize_with(new.len() + padding as usize, || rng.gen());

        Ok(new)
    }

    fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<B, Self::Err> {
        if self.talg.cipher.is_some() {
            self.talg
                .cipher
                .encrypt(&self.tchain.key, &self.tchain.iv, buf.as_mut())?;
        }

        Ok(buf)
    }

    fn seal(&mut self, mut buf: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        if self.talg.hmac.etm() {
            self.encrypt(&mut buf[4..])?;
            buf.append(
                &mut self
                    .talg
                    .hmac
                    .sign(self.tseq, buf.as_ref(), &self.tchain.hmac),
            );
        } else {
            let mut mac = self
                .talg
                .hmac
                .sign(self.tseq, buf.as_ref(), &self.tchain.hmac);

            self.encrypt(&mut buf[4..])?;
            buf.append(&mut mac);
        }

        Ok(buf)
    }
}
