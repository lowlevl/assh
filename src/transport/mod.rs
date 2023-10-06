use rand::Rng;
use ssh_packet::{Mac, OpeningCipher, SealingCipher};

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

        let size = if self.cipher.is_some() && self.hmac.etm() {
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
    type Mac = algorithm::Hmac;

    fn mac(&self) -> &Self::Mac {
        &self.talg.hmac
    }

    fn block_size(&self) -> usize {
        self.talg.cipher.block_size()
    }

    fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<(), Self::Err> {
        if self.ralg.cipher.is_some() {
            self.ralg
                .cipher
                .decrypt(&self.rchain.key, &self.rchain.iv, buf.as_mut())?;
        }

        Ok(())
    }

    fn open<B: AsRef<[u8]>>(&mut self, buf: B, mac: Vec<u8>) -> Result<(), Self::Err> {
        if OpeningCipher::mac(self).size() > 0 {
            self.ralg
                .hmac
                .verify(self.rseq, buf.as_ref(), &self.rchain.hmac, &mac)?;
        }

        Ok(())
    }

    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        self.ralg.compress.decompress(buf)
    }
}

impl SealingCipher for TransportPair {
    type Err = Error;
    type Mac = algorithm::Hmac;

    fn mac(&self) -> &Self::Mac {
        &self.talg.hmac
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

    fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<(), Self::Err> {
        if self.talg.cipher.is_some() {
            self.talg
                .cipher
                .encrypt(&self.tchain.key, &self.tchain.iv, buf.as_mut())?;
        }

        Ok(())
    }

    fn seal<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err> {
        Ok(self
            .talg
            .hmac
            .sign(self.tseq, buf.as_ref(), &self.tchain.hmac))
    }
}
