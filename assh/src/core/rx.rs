use std::{io, pin::Pin, task};

use bytes::{Buf, Bytes, BytesMut};
use digest::{Digest, FixedOutputReset};
use futures::AsyncRead;

use super::{
    LEN_FIELD_SIZE, PACKET_MAX_SIZE, PACKET_MIN_READ, PACKET_MIN_SIZE, PAYLOAD_MAX_LEN,
    algorithm::{cipher, compress, hmac, kex},
};
use crate::{Error, Result};

// TODO (performance): handle larger payload sizes if peer is known to support them ?

#[derive(Debug, Default)]
pub struct Reader {
    bytes: BytesMut,
    amt: usize,
}

impl Reader {
    pub fn grow(&mut self, new_len: usize) {
        self.bytes.resize(new_len, 0);
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn poll_fill(
        &mut self,
        cx: &mut task::Context<'_>,
        mut rdr: impl AsyncRead + Unpin,
    ) -> task::Poll<io::Result<bool>> {
        while self.amt < self.bytes.len() {
            let n = futures::ready!(Pin::new(&mut rdr).poll_read(cx, &mut self.bytes[self.amt..]))?;
            if n == 0 {
                return task::Poll::Ready(Ok(true));
            }

            self.amt += n;
        }

        task::Poll::Ready(Ok(false))
    }

    pub fn get_mut(&mut self) -> &mut BytesMut {
        &mut self.bytes
    }

    pub fn into_inner(self) -> BytesMut {
        self.bytes
    }
}

#[derive(Debug, Default)]
pub struct Transport {
    compress: compress::State<compress::Decompression>,
    cipher: cipher::DecState,
    hmac: hmac::State,
}

impl Transport {
    pub fn as_server<H: Digest + FixedOutputReset>(
        client: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        Self {
            compress: compress::State::<compress::Decompression>::new(&client.compress),
            cipher: cipher::DecState::new::<b'A', b'C', H>(
                &client.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'E', H>(&client.hmac, secret, hash, session_id),
        }
    }

    pub fn as_client<H: Digest + FixedOutputReset>(
        server: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        Self {
            compress: compress::State::<compress::Decompression>::new(&server.compress),
            cipher: cipher::DecState::new::<b'B', b'D', H>(
                &server.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'F', H>(&server.hmac, secret, hash, session_id),
        }
    }

    pub fn initial_block(&self) -> usize {
        PACKET_MIN_READ.max(self.cipher.block_size())
    }

    pub fn decrypt_length(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.hmac.etm() {
            self.cipher.decrypt(&mut buf[..])?;
        }

        let len = {
            let mut bytes = [0; LEN_FIELD_SIZE];
            bytes.copy_from_slice(&buf[..LEN_FIELD_SIZE]);

            u32::from_be_bytes(bytes) as usize
        };

        if LEN_FIELD_SIZE + len < PACKET_MIN_SIZE.max(self.cipher.block_size()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "packet size too small: {} < {}",
                    LEN_FIELD_SIZE + len,
                    PACKET_MIN_SIZE
                ),
            )
            .into());
        }

        let size = LEN_FIELD_SIZE + len + self.hmac.size();
        if size > PACKET_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("packet size too large: {size} > {}", PACKET_MAX_SIZE),
            )
            .into());
        }

        Ok(size)
    }

    pub fn decrypt(&mut self, seq: u32, mut buf: BytesMut, authenticated: bool) -> Result<Bytes> {
        let mac = buf.split_off(buf.len() - self.hmac.size());

        if self.hmac.etm() {
            // Encrypt-Then-MAC

            self.hmac.verify(seq, &buf, &mac)?;
            self.cipher.decrypt(&mut buf[LEN_FIELD_SIZE..])?;
        } else {
            // MAC-Then-Encrypt

            self.cipher.decrypt(&mut buf[self.initial_block()..])?;
            self.hmac.verify(seq, &buf, &mac)?;
        }

        // skip the length field
        buf.advance(LEN_FIELD_SIZE);

        let padlen = buf.get_u8() as usize;
        if padlen >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("padding too large: {padlen} >= {}", buf.len()),
            )
            .into());
        }

        // truncate padding
        buf.truncate(buf.len() - padlen);

        // FIXME: this might be required
        // if buf.len() > PAYLOAD_MAX_LEN {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidData,
        //         format!(
        //             "payload size too large: {} > {}",
        //             buf.len(),
        //             PAYLOAD_MAX_LEN
        //         ),
        //     )
        //     .into());
        // }

        self.compress
            .decompress(buf, PAYLOAD_MAX_LEN, authenticated)
            .map_err(|err| Error::Zlib(format!("{err:?}")))
    }
}
