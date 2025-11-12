//! Primitives to manipulate binary data to extract and encode
//! messages from/to a [`Pipe`] stream.

use std::io;

use futures::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_time::{future::FutureExt as _, time::Duration};
use ssh_packet::IntoPacket;

use crate::{Pipe, Result, algorithm};

mod counter;
use counter::IoCounter;

mod transport;
pub(super) use transport::{Transport, TransportPair};

mod keys;
pub(super) use keys::Keys;

#[doc(no_inline)]
pub use ssh_packet::Packet;

/// Re-key after 1GiB of exchanged data as recommended per the RFC.
const REKEY_BYTES_THRESHOLD: usize = 0x40000000;

/// A wrapper around a [`Pipe`] to interface with to the SSH binary protocol.
pub struct Stream<S> {
    inner: IoCounter<S>,
    timeout: Duration,

    /// The pair of transport algorithms and keys computed from the key exchange.
    transport: TransportPair,

    /// The session identifier derived from the first key exchange.
    session: Option<Vec<u8>>,

    /// Sequence number for the `tx` side.
    txseq: u32,

    /// Sequence number for the `rx` side.
    rxseq: u32,

    /// A buffer for the `peek` method.
    buffer: Option<Packet>,
}

impl<S> Stream<S>
where
    S: Pipe,
{
    pub fn new(stream: S, timeout: Duration) -> Self {
        Self {
            inner: IoCounter::new(stream),
            timeout,
            transport: Default::default(),
            session: None,
            txseq: 0,
            rxseq: 0,
            buffer: None,
        }
    }

    pub fn is_rekeyable(&self) -> bool {
        self.session.is_none() || self.inner.count() > REKEY_BYTES_THRESHOLD
    }

    pub fn with_transport(&mut self, transport: TransportPair) {
        self.transport = transport;
        self.inner.reset();
    }

    pub fn with_session(&mut self, session: &[u8]) -> &[u8] {
        self.session.get_or_insert_with(|| session.to_vec())
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        self.session.as_deref()
    }

    pub async fn fill_buf(&mut self) -> Result<()> {
        self.inner.fill_buf().await?;

        Ok(())
    }

    /// Receive and decrypt a _packet_ from the peer without removing it from the queue.
    pub async fn peek(&mut self) -> Result<&Packet> {
        let packet = self.recv().await?;

        Ok(self.buffer.insert(packet))
    }

    /// Receive and decrypt a _packet_ from the peer.
    pub async fn recv(&mut self) -> Result<Packet> {
        match self.buffer.take() {
            Some(packet) => Ok(packet),
            None => {
                let packet = Self::inner_recv(&mut self.inner, &mut self.transport.rx, self.rxseq)
                    .timeout(self.timeout)
                    .await??;

                tracing::trace!(
                    "<~- #{}: ^{:#x} ({} bytes)",
                    self.rxseq,
                    packet[0],
                    packet.len(),
                );

                self.rxseq = self.rxseq.wrapping_add(1);

                Ok(packet)
            }
        }
    }

    /// Encrypt and send a _packet_ to the peer.
    pub async fn send(&mut self, packet: impl IntoPacket) -> Result<()> {
        let packet = packet.into_packet();

        Self::inner_send(&mut self.inner, &mut self.transport.tx, self.txseq, &packet)
            .timeout(self.timeout)
            .await??;
        self.inner.flush().await?;

        tracing::trace!(
            "-~> #{}: ^{:#x} ({} bytes)",
            self.txseq,
            packet[0],
            packet.len(),
        );

        self.txseq = self.txseq.wrapping_add(1);

        Ok(())
    }

    async fn inner_recv(
        mut reader: impl AsyncRead + Unpin,
        cipher: &mut Transport,
        seq: u32,
    ) -> Result<Packet> {
        let mut buf = vec![0; cipher.block_size()];
        reader.read_exact(&mut buf[..]).await?;

        if !cipher.hmac.etm() {
            cipher.decrypt(&mut buf[..])?;
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
        reader.read_exact(&mut buf[cipher.block_size()..]).await?;

        let mut mac = vec![0; cipher.hmac.size()];
        reader.read_exact(&mut mac[..]).await?;

        if cipher.hmac.etm() {
            cipher.open(&buf, mac, seq)?;
            cipher.decrypt(&mut buf[4..])?;
        } else {
            cipher.decrypt(&mut buf[cipher.block_size()..])?;
            cipher.open(&buf, mac, seq)?;
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
            ))?;
        }

        let mut payload = vec![0; len as usize - *padlen as usize - std::mem::size_of_val(padlen)];
        io::Read::read_exact(&mut decrypted, &mut payload[..])?;

        let payload = cipher.decompress(payload)?;

        Ok(Packet(payload))
    }

    async fn inner_send(
        mut writer: impl AsyncWrite + Unpin,
        cipher: &mut Transport,
        seq: u32,
        packet: &Packet,
    ) -> Result<()> {
        let compressed = cipher.compress(packet.as_ref())?;

        let buf = cipher.pad(compressed)?;
        let mut buf = [(buf.len() as u32).to_be_bytes().to_vec(), buf].concat();

        let (buf, mac) = if cipher.hmac.etm() {
            cipher.encrypt(&mut buf[4..])?;
            let mac = cipher.seal(&buf, seq)?;

            (buf, mac)
        } else {
            let mac = cipher.seal(&buf, seq)?;
            cipher.encrypt(&mut buf[..])?;

            (buf, mac)
        };

        writer.write_all(&buf).await?;
        writer.write_all(&mac).await?;

        Ok(())
    }
}
