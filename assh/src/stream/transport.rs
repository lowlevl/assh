use rand::RngExt;
use secrecy::ExposeSecret;
use ssh_packet::Packet;

use crate::{
    Result,
    stream::algorithm::{cipher, compress, hmac},
};

use super::Keys;

#[derive(Debug, Default)]
pub struct TransportPair {
    pub tx: Transport,
    pub rx: Transport,
}

#[derive(Debug, Default)]
pub struct Transport {
    pub compress: compress::Compress,
    pub cipher: cipher::Cipher,
    pub hmac: hmac::State,

    pub state: Option<cipher::State>,
    pub chain: Keys,
}

impl Transport {
    pub fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    pub fn decrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<()> {
        if self.cipher != cipher::Cipher::None {
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
        self.hmac
            .verify(seq, buf.as_ref(), &mac)
            .map_err(Into::into)
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
        let mut rng = rand::rng();

        let padding = self.padding(buf.len());

        // prefix with the size
        let mut padded = vec![padding];
        padded.append(&mut buf);

        // fill with random
        padded.resize_with(padded.len() + padding as usize, || rng.random());

        Ok(padded)
    }

    pub fn encrypt<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<()> {
        if self.cipher != cipher::Cipher::None {
            self.cipher.encrypt(
                &mut self.state,
                self.chain.key.expose_secret(),
                self.chain.iv.expose_secret(),
                buf.as_mut(),
            )?;
        }

        Ok(())
    }

    pub fn seal<B: AsRef<[u8]>>(&mut self, buf: B, seq: u32) -> hmac::HmacBuf {
        self.hmac.compute(seq, buf.as_ref())
    }
}
