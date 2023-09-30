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

impl OpeningCipher for TransportPair {
    type Err = ssh_key::Error;

    fn size(&self) -> usize {
        0
    }

    fn open(&mut self, packet: ssh_packet::Packet) -> Result<Vec<u8>, Self::Err> {
        todo!()
    }
}

impl SealingCipher for TransportPair {
    type Err = ssh_key::Error;

    fn seal(&mut self, payload: Vec<u8>) -> Result<Packet, Self::Err> {
        todo!()
    }
}
