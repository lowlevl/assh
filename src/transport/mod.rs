use rand::Rng;
use ssh_packet::{CipherCore, Mac, OpeningCipher, SealingCipher};

mod keychain;
pub use keychain::KeyChain;

use crate::{
    algorithm::{self, Cipher},
    Error, Result,
};

#[derive(Debug, Default)]
pub struct TransportPair {
    pub rx: Transport<algorithm::DecryptorCipher>,
    pub tx: Transport<algorithm::EncryptorCipher>,
}

#[derive(Debug, Default)]
pub struct Transport<T> {
    pub chain: KeyChain,
    pub cipher: T,
    pub hmac: algorithm::Hmac,
    pub compress: algorithm::Compress,
}

impl<T: Cipher> CipherCore for Transport<T> {
    type Err = Error;
    type Mac = algorithm::Hmac;

    fn mac(&self) -> &Self::Mac {
        &self.hmac
    }

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }
}

impl OpeningCipher for Transport<algorithm::DecryptorCipher> {
    fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<(), Self::Err> {
        if self.cipher.is_some() {
            self.cipher
                .decrypt(&self.chain.key, &self.chain.iv, buf.as_mut())?;
        }

        Ok(())
    }

    fn open<B: AsRef<[u8]>>(&mut self, buf: B, mac: Vec<u8>, seq: u32) -> Result<(), Self::Err> {
        if self.mac().size() > 0 {
            self.hmac
                .verify(seq, buf.as_ref(), &self.chain.hmac, &mac)?;
        }

        Ok(())
    }

    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        self.compress.decompress(buf)
    }
}

impl SealingCipher for Transport<algorithm::EncryptorCipher> {
    fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err> {
        self.compress.compress(buf.as_ref())
    }

    fn pad(&mut self, buf: Vec<u8>, padding: u8) -> Result<Vec<u8>, Self::Err> {
        let mut rng = rand::thread_rng();

        // prefix with the size
        let mut new = vec![padding];
        new.extend_from_slice(&buf);

        // fill with random
        new.resize_with(new.len() + padding as usize, || rng.gen());

        Ok(new)
    }

    fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<(), Self::Err> {
        if self.cipher.is_some() {
            self.cipher
                .encrypt(&self.chain.key, &self.chain.iv, buf.as_mut())?;
        }

        Ok(())
    }

    fn seal<B: AsRef<[u8]>>(&mut self, buf: B, seq: u32) -> Result<Vec<u8>, Self::Err> {
        Ok(self.hmac.sign(seq, buf.as_ref(), &self.chain.hmac))
    }
}
