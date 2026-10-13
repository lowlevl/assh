use bytes::{BufMut, Bytes};
use digest::{Digest, FixedOutputReset};
use ssh_packet::Packet;

use super::{
    LEN_FIELD_SIZE, PADLEN_FIELD_SIZE,
    algorithm::{cipher, compress, hmac, kex},
};
use crate::{Error, Result};

// TODO (performance): produce larger payload sizes if peer is known to support them ?

#[derive(Debug, Default)]
pub struct Transport {
    compress: compress::State<compress::Compression>,
    cipher: cipher::EncState,
    hmac: hmac::State,
}

impl Transport {
    pub fn as_client<H: Digest + FixedOutputReset>(
        client: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        Self {
            compress: compress::State::<compress::Compression>::new(&client.compress),
            cipher: cipher::EncState::new::<b'A', b'C', H>(
                &client.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'E', H>(&client.hmac, secret, hash, session_id),
        }
    }

    pub fn as_server<H: Digest + FixedOutputReset>(
        server: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        Self {
            compress: compress::State::<compress::Compression>::new(&server.compress),
            cipher: cipher::EncState::new::<b'B', b'D', H>(
                &server.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'F', H>(&server.hmac, secret, hash, session_id),
        }
    }

    // TODO (security): implement variable length padding
    fn padding(&self, psize: usize) -> usize {
        const MIN_PAD_SIZE: usize = 4;
        const MIN_ALIGN: usize = 8;

        let size = if self.hmac.etm() {
            PADLEN_FIELD_SIZE + psize
        } else {
            LEN_FIELD_SIZE + PADLEN_FIELD_SIZE + psize
        };

        let align = self.cipher.block_size().max(MIN_ALIGN);
        let padding = align - size % align;

        let padding = if padding < MIN_PAD_SIZE {
            padding + align
        } else {
            padding
        };

        if size + padding < self.cipher.block_size().max(Packet::MIN_SIZE) {
            padding + align
        } else {
            padding
        }
    }

    pub fn encrypt(&mut self, seq: u32, payload: &[u8], authenticated: bool) -> Result<Bytes> {
        // NOTE: this is a capacity to avoid reallocating while assembling the payload,
        // this however goes down the drain with compression and reallocates at least once.
        let capacity = LEN_FIELD_SIZE
            + PADLEN_FIELD_SIZE
            + payload.len()
            + self.padding(payload.len())
            + self.hmac.size();
        let mut buf = bytes::BytesMut::with_capacity(capacity);

        let mut padded = buf.split_off(LEN_FIELD_SIZE); // reserve 4 bytes for `length`.
        let mut unpadded = padded.split_off(PADLEN_FIELD_SIZE); // reserve 1 byte for `padding`.

        self.compress
            .compress(payload, &mut unpadded, authenticated)
            .map_err(|err| Error::Zlib(format!("{err:?}")))?;

        let padlen = self.padding(unpadded.len());
        unpadded.extend(rand::random_iter::<u8>().take(padlen));

        // preprend `padlen`
        padded.put_u8(padlen as u8);
        padded.unsplit(unpadded);

        // preprend `length`
        buf.put_u32(padded.len() as u32);
        buf.unsplit(padded);

        let mac;
        if self.hmac.etm() {
            // Encrypt-Then-MAC

            self.cipher.encrypt(&mut buf[LEN_FIELD_SIZE..])?;
            mac = self.hmac.compute(seq, &buf);
        } else {
            // MAC-Then-Encrypt

            mac = self.hmac.compute(seq, &buf);
            self.cipher.encrypt(&mut buf[..])?;
        }

        buf.extend_from_slice(&mac);

        Ok(buf.freeze())
    }
}
