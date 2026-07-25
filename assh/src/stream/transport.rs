use digest::{Digest, FixedOutputReset};
use rand::RngExt;
use ssh_packet::Packet;

use crate::{
    Result,
    stream::algorithm::{cipher, compress, hmac, kex},
};

#[derive(Debug, Default)]
pub struct Transport {
    pub tx: TxTransport,
    pub rx: RxTransport,
}

impl Transport {
    pub fn as_client<H: Digest + FixedOutputReset>(
        client: kex::KexMeta<'_>,
        server: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        let tx = TxTransport {
            compress: client.compress,
            cipher: cipher::EncState::new::<b'A', b'C', H>(
                &client.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'E', H>(&client.hmac, secret, hash, session_id),
        };

        let rx = RxTransport {
            compress: server.compress,
            cipher: cipher::DecState::new::<b'B', b'D', H>(
                &server.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'F', H>(&server.hmac, secret, hash, session_id),
        };

        Self { tx, rx }
    }

    pub fn as_server<H: Digest + FixedOutputReset>(
        server: kex::KexMeta<'_>,
        client: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        let tx = TxTransport {
            compress: server.compress,
            cipher: cipher::EncState::new::<b'B', b'D', H>(
                &server.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'F', H>(&server.hmac, secret, hash, session_id),
        };

        let rx = RxTransport {
            compress: client.compress,
            cipher: cipher::DecState::new::<b'A', b'C', H>(
                &client.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'E', H>(&client.hmac, secret, hash, session_id),
        };

        Self { tx, rx }
    }
}

#[derive(Debug, Default)]
pub struct TxTransport {
    pub compress: compress::Compress,
    pub cipher: cipher::EncState,
    pub hmac: hmac::State,
}

impl TxTransport {
    fn padding(&self, payload: usize) -> u8 {
        const MIN_PAD_SIZE: usize = 4;
        const MIN_ALIGN: usize = 8;

        let align = self.cipher.block_size().max(MIN_ALIGN);

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

        if size + padding < self.cipher.block_size().max(Packet::MIN_SIZE) {
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
}

#[derive(Debug, Default)]
pub struct RxTransport {
    pub compress: compress::Compress,
    pub cipher: cipher::DecState,
    pub hmac: hmac::State,
}
