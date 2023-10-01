use rand::RngCore;
use ssh_packet::{OpeningCipher, Packet, SealingCipher};

mod compress;
pub use compress::{CompressAlg, CompressPair};

mod encrypt;
pub use encrypt::{EncryptAlg, EncryptPair};

mod hmac;
pub use hmac::{HmacAlg, HmacPair};

mod kex;
pub use kex::KexAlg;

#[derive(Debug, Default)]
pub struct TransportPair {
    pub encrypt: encrypt::EncryptPair,
    pub hmac: hmac::HmacPair,
    pub compress: compress::CompressPair,
}

impl TransportPair {
    pub const MIN_PACKET_SIZE: usize = 16;
    pub const MIN_PAD_SIZE: usize = 4;
    pub const MIN_ALIGN: usize = 8;

    pub fn padding(&self, payload: usize) -> usize {
        let align = self.encrypt.tx.block_size().max(Self::MIN_ALIGN);

        let size = std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + payload;
        let padding = align - size % align;

        let padding = if padding < Self::MIN_PAD_SIZE {
            padding + align
        } else {
            padding
        };

        if size + padding < self.encrypt.tx.block_size().max(Self::MIN_PACKET_SIZE) {
            padding + align
        } else {
            padding
        }
    }
}

impl OpeningCipher for TransportPair {
    type Err = ssh_key::Error;

    fn size(&self) -> usize {
        self.hmac.rx.size()
    }

    fn open(&mut self, packet: ssh_packet::Packet) -> Result<Vec<u8>, Self::Err> {
        if !self.hmac.rx.verify(&packet) {
            return Err(ssh_key::Error::Crypto);
        }

        // TODO: Verify padding

        let mut payload = self.compress.rx.decompress(packet.payload);

        if self.encrypt.rx.is_some() {
            self.encrypt.rx.decrypt(&[], &[], &mut payload, None)?;
        }

        Ok(payload)
    }
}

impl SealingCipher for TransportPair {
    type Err = ssh_key::Error;

    fn seal(&mut self, mut payload: Vec<u8>) -> Result<Packet, Self::Err> {
        if self.encrypt.tx.is_some() {
            self.encrypt.tx.encrypt(&[], &[], &mut payload)?;
        }

        let payload = self.compress.tx.compress(payload);
        let mut padding = vec![0u8; self.padding(payload.len())];
        rand::thread_rng().fill_bytes(&mut padding[..]);

        let mac = self.hmac.tx.sign(&payload);

        Ok(Packet {
            payload,
            padding,
            mac,
        })
    }
}
