use std::io;

use digest::{Digest, FixedOutputReset};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    compress: compress::Compress,
    cipher: cipher::EncState,
    hmac: hmac::State,
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

    fn pad(&mut self, mut buf: Vec<u8>) -> Result<Vec<u8>> {
        let mut rng = rand::rng();

        let padding = self.padding(buf.len());

        // prefix with the size
        let mut padded = vec![padding];
        padded.append(&mut buf);

        // fill with random
        padded.resize_with(padded.len() + padding as usize, || rng.random());

        Ok(padded)
    }

    pub async fn tx(
        &mut self,
        seq: u32,
        data: &[u8],
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<()> {
        let compressed = self.compress.compress(data)?;

        let buf = self.pad(compressed)?;
        let mut buf = [(buf.len() as u32).to_be_bytes().to_vec(), buf].concat();

        let mac;
        if self.hmac.etm() {
            // Encrypt-Then-MAC

            self.cipher.encrypt(&mut buf[4..])?;
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
    compress: compress::Compress,
    cipher: cipher::DecState,
    hmac: hmac::State,
}

impl RxTransport {
    pub async fn rx(&mut self, seq: u32, mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
        let mut buf = vec![0; self.cipher.block_size()];
        reader.read_exact(&mut buf[..]).await?;

        if !self.hmac.etm() {
            self.cipher.decrypt(&mut buf[..])?;
        }

        let len = u32::from_be_bytes(
            buf[..4]
                .try_into()
                .expect("the buffer of size 4 is not of size 4"),
        );

        if len as usize > Packet::MAX_SIZE {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("payload size too large, {len} > {}", Packet::MAX_SIZE),
            ))?
        }

        // read the rest of the data from the reader
        buf.resize(std::mem::size_of_val(&len) + len as usize, 0);
        reader
            .read_exact(&mut buf[self.cipher.block_size()..])
            .await?;

        let mut mac = vec![0; self.hmac.size()];
        reader.read_exact(&mut mac[..]).await?;

        if self.hmac.etm() {
            self.hmac.verify(seq, &buf, &mac)?;
            self.cipher.decrypt(&mut buf[4..])?;
        } else {
            self.cipher.decrypt(&mut buf[self.cipher.block_size()..])?;
            self.hmac.verify(seq, &buf, &mac)?;
        }

        let (padlen, mut decrypted) = buf[4..].split_first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unable to read padding length",
            )
        })?;

        if *padlen as usize > len as usize - 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("padding size too large, {padlen} > {} - 1", len),
            )
            .into());
        }

        let mut payload = vec![0; len as usize - *padlen as usize - std::mem::size_of_val(padlen)];
        io::Read::read_exact(&mut decrypted, &mut payload[..])?;

        let payload = self.compress.decompress(payload)?;

        Ok(payload)
    }
}
