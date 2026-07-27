use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use digest::{Digest, FixedOutputReset};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ssh_packet::Packet;

use crate::{
    Result,
    stream::algorithm::{cipher, compress, hmac, kex},
};

// TODO (performance): handle & produce larger payload sizes if peer is known to support them ?

const LEN_FIELD_SIZE: usize = std::mem::size_of::<u32>();
const PADLEN_FIELD_SIZE: usize = std::mem::size_of::<u8>();

/// Per RFC4253, all implementations MUST be able to process packets
/// with an uncompressed payload length of 32768 bytes or less.
const PAYLOAD_MAX_LEN: usize = 32768;

/// Per RFC4253, all implementations MUST be able to process [...]
/// a total packet size of 35000 bytes or less.
const PACKET_MAX_SIZE: usize = 35000;

/// Per RFC4253, the minimum size of a packet is 16
/// (or the cipher block size, whichever is larger).
///
/// NOTE: OpenSSH produces 12 bytes packets with `3des-cbc`, so this is the value.
const PACKET_MIN_SIZE: usize = 12;

/// Per RFC4253, implementations SHOULD decrypt the length after receiving
/// the first 8 (or cipher block size, whichever is larger) bytes of a packet.
const PACKET_MIN_READ: usize = 8;

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
            compress: compress::State::<compress::Compression>::new(&client.compress),
            cipher: cipher::EncState::new::<b'A', b'C', H>(
                &client.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'E', H>(&client.hmac, secret, hash, session_id),
        };

        let rx = RxTransport {
            compress: compress::State::<compress::Decompression>::new(&server.compress),
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
        client: kex::KexMeta<'_>,
        server: kex::KexMeta<'_>,
        secret: &[u8],
        hash: &[u8],
        session_id: &[u8],
    ) -> Self {
        let tx = TxTransport {
            compress: compress::State::<compress::Compression>::new(&server.compress),
            cipher: cipher::EncState::new::<b'B', b'D', H>(
                &server.cipher,
                secret,
                hash,
                session_id,
            ),
            hmac: hmac::State::new::<b'F', H>(&server.hmac, secret, hash, session_id),
        };

        let rx = RxTransport {
            compress: compress::State::<compress::Decompression>::new(&client.compress),
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
    compress: compress::State<compress::Compression>,
    cipher: cipher::EncState,
    hmac: hmac::State,
}

impl TxTransport {
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

    pub async fn write(
        &mut self,
        seq: u32,
        payload: &[u8],
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<()> {
        let capacity =
            LEN_FIELD_SIZE + PADLEN_FIELD_SIZE + payload.len() + self.padding(payload.len());
        let mut buf = bytes::BytesMut::with_capacity(capacity);

        let mut padded = buf.split_off(LEN_FIELD_SIZE); // reserve 4 bytes for `length`.
        let mut unpadded = padded.split_off(PADLEN_FIELD_SIZE); // reserve 1 byte for `padding`.

        self.compress.compress(payload, &mut unpadded)?;

        let padlen = self.padding(unpadded.len());
        unpadded.extend(rand::random_iter::<u8>().take(padlen));

        // preprend `padlen`
        padded.put_u8(padlen as u8);
        padded.unsplit(unpadded);

        // preprend `length`
        buf.put_u32(padded.len() as u32);
        buf.unsplit(padded);

        debug_assert_eq!(
            buf.capacity(),
            capacity,
            "the `buf` was reallocated while writing"
        );

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

        writer.write_all(&buf).await?;
        writer.write_all(&mac).await?;

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RxTransport {
    compress: compress::State<compress::Decompression>,
    cipher: cipher::DecState,
    hmac: hmac::State,
}

impl RxTransport {
    pub async fn read(&mut self, seq: u32, mut reader: impl AsyncRead + Unpin) -> Result<Bytes> {
        let initial = PACKET_MIN_READ.max(self.cipher.block_size());
        let mut buf = BytesMut::zeroed(initial);

        // receive the initial block
        reader.read_exact(&mut buf[..]).await?;

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

        // read the remaining data
        buf.resize(size, 0);
        reader.read_exact(&mut buf[initial..]).await?;

        let mac = buf.split_off(buf.len() - self.hmac.size());
        if self.hmac.etm() {
            // Encrypt-Then-MAC

            self.hmac.verify(seq, &buf, &mac)?;
            self.cipher.decrypt(&mut buf[LEN_FIELD_SIZE..])?;
        } else {
            // MAC-Then-Encrypt

            self.cipher.decrypt(&mut buf[initial..])?;
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

        if buf.len() > PAYLOAD_MAX_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "payload size too large: {} > {}",
                    buf.len(),
                    PAYLOAD_MAX_LEN
                ),
            )
            .into());
        }

        // FIXME: check PAYLOAD_MAX_LEN in decompress
        Ok(self.compress.decompress(buf)?)
    }
}
