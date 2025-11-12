use rand::Rng;
use secrecy::ExposeSecret;
use ssh_packet::Packet;

use crate::{
    Result,
    stream::algorithm::{self, Cipher, CipherState},
};

use super::Keys;

#[derive(Debug, Default)]
pub struct TransportPair {
    pub tx: Transport,
    pub rx: Transport,
}

#[derive(Debug, Default)]
pub struct Transport {
    pub compress: algorithm::Compress,
    pub cipher: algorithm::Cipher,
    pub hmac: algorithm::Hmac,

    pub state: Option<CipherState>,
    pub chain: Keys,
}

impl Transport {
    pub fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    pub fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<()> {
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

    pub fn open<B: AsRef<[u8]>>(&mut self, buf: B, mac: Vec<u8>, seq: u32) -> Result<()> {
        if self.hmac.size() > 0 {
            self.hmac
                .verify(seq, buf.as_ref(), self.chain.hmac.expose_secret(), &mac)?;
        }

        Ok(())
    }

    pub fn decompress(&mut self, buf: Vec<u8>) -> Result<Vec<u8>> {
        self.compress.decompress(buf)
    }

    pub fn compress<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<Vec<u8>> {
        self.compress.compress(buf.as_ref())
    }

    fn padding(&self, payload: usize) -> u8 {
        const MIN_PAD_SIZE: usize = 4;
        const MIN_ALIGN: usize = 8;

        let align = self.block_size().max(MIN_ALIGN);

        let size = if self.hmac.etm() {
            std::mem::size_of::<u8>() + payload
        } else {
            std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + payload
        };
        let padding = align - size % align;

        let padding = if padding < MIN_PAD_SIZE {
            padding + align
        } else {
            padding
        };

        if size + padding < self.block_size().max(Packet::MIN_SIZE) {
            (padding + align) as u8
        } else {
            padding as u8
        }
    }

    pub fn pad(&mut self, mut buf: Vec<u8>) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        let padding = self.padding(buf.len());

        // prefix with the size
        let mut padded = vec![padding];
        padded.append(&mut buf);

        // fill with random
        padded.resize_with(padded.len() + padding as usize, || rng.r#gen());

        Ok(padded)
    }

    pub fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<()> {
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

    pub fn seal<B: AsRef<[u8]>>(&mut self, buf: B, seq: u32) -> Result<Vec<u8>> {
        Ok(self
            .hmac
            .sign(seq, buf.as_ref(), self.chain.hmac.expose_secret()))
    }
}
