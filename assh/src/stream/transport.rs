use rand::Rng;
use secrecy::ExposeSecret;
use ssh_packet::{CipherCore, Mac, OpeningCipher, SealingCipher};

use crate::{
    stream::algorithm::{self, Cipher, CipherState},
    Error, Result,
};

use super::Keys;

#[derive(Debug, Default)]
pub struct TransportPair {
    pub rx: Transport,
    pub tx: Transport,
}

#[derive(Debug, Default)]
pub struct Transport {
    pub chain: Keys,
    pub state: Option<CipherState>,
    pub cipher: algorithm::Cipher,
    pub hmac: algorithm::Hmac,
    pub compress: algorithm::Compress,
}

impl CipherCore for Transport {
    type Err = Error;
    type Mac = algorithm::Hmac;

    fn mac(&self) -> &Self::Mac {
        &self.hmac
    }

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }
}

impl OpeningCipher for Transport {
    fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<(), Self::Err> {
        if self.cipher != Cipher::None {
            self.cipher.decrypt(
                &mut self.state,
                self.chain.key.expose_secret(),
                self.chain.iv.expose_secret(),
                buf.as_mut(),
            )?;
        }

        Ok(())
    }

    fn open<B: AsRef<[u8]>>(&mut self, buf: B, mac: Vec<u8>, seq: u32) -> Result<(), Self::Err> {
        if self.mac().size() > 0 {
            self.hmac
                .verify(seq, buf.as_ref(), self.chain.hmac.expose_secret(), &mac)?;
        }

        Ok(())
    }

    fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>, Self::Err> {
        self.compress.decompress(buf)
    }
}

impl SealingCipher for Transport {
    fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>, Self::Err> {
        self.compress.compress(buf.as_ref())
    }

    fn pad(&mut self, mut buf: Vec<u8>, padding: u8) -> Result<Vec<u8>, Self::Err> {
        let mut rng = rand::thread_rng();

        // prefix with the size
        let mut padded = vec![padding];
        padded.append(&mut buf);

        // fill with random
        padded.resize_with(padded.len() + padding as usize, || rng.gen());

        Ok(padded)
    }

    fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<(), Self::Err> {
        if self.cipher != Cipher::None {
            self.cipher.encrypt(
                &mut self.state,
                self.chain.key.expose_secret(),
                self.chain.iv.expose_secret(),
                buf.as_mut(),
            )?;
        }

        Ok(())
    }

    fn seal<B: AsRef<[u8]>>(&mut self, buf: B, seq: u32) -> Result<Vec<u8>, Self::Err> {
        Ok(self
            .hmac
            .sign(seq, buf.as_ref(), self.chain.hmac.expose_secret()))
    }
}
