//! Primitives to manipulate binary data to extract and encode
//! messages from/to an [`AsyncBufRead`] + [`AsyncWrite`] stream.

use futures::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use futures_time::{future::FutureExt, time::Duration};
use ssh_packet::{Packet, ToPacket};

use crate::Result;

mod counter;
use counter::IoCounter;

mod transport;
pub use transport::{Transport, TransportPair};

mod keys;
pub use keys::Keys;

/// Re-key after 1GiB of exchanged data as recommended per the RFC.
const REKEY_BYTES_THRESHOLD: usize = 0x40000000;

/// A wrapper around [`AsyncBufRead`] + [`AsyncWrite`]
/// to interface with to the SSH binary protocol.
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

impl<S: AsyncBufRead + AsyncWrite + Unpin> Stream<S> {
    pub(crate) fn new(stream: S, timeout: Duration) -> Self {
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

    pub(crate) fn with_session(&mut self, session: &[u8]) -> &[u8] {
        self.session.get_or_insert_with(|| session.to_vec())
    }

    pub(crate) fn with_transport(&mut self, transport: TransportPair) {
        self.transport = transport;
        self.inner.reset();
    }

    /// Returns whether the stream should be re-keyed.
    pub(crate) fn is_rekeyable(&self) -> bool {
        self.session.is_none() || self.inner.count() > REKEY_BYTES_THRESHOLD
    }

    /// Poll the stream to detect whether there is some pending data to be read.
    pub async fn is_readable(&mut self) -> Result<bool> {
        Ok(self
            .inner
            .fill_buf()
            .timeout(Duration::from_millis(1))
            .await
            .ok()
            .transpose()?
            .map(|buf| !buf.is_empty())
            .unwrap_or_default())
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
                let packet =
                    Packet::from_async_reader(&mut self.inner, &mut self.transport.rx, self.rxseq)
                        .timeout(self.timeout)
                        .await??;

                self.rxseq = self.rxseq.wrapping_add(1);

                tracing::trace!("<-({}): {} bytes", self.rxseq - 1, packet.payload.len());

                Ok(packet)
            }
        }
    }

    /// Encrypt and send a _packet_ to the peer.
    pub async fn send(&mut self, packet: &impl ToPacket) -> Result<()> {
        let packet = packet.to_packet()?;

        packet
            .to_async_writer(&mut self.inner, &mut self.transport.tx, self.txseq)
            .timeout(self.timeout)
            .await??;
        self.inner.flush().await?;

        self.txseq = self.txseq.wrapping_add(1);

        tracing::trace!("({})->: {} bytes", self.txseq - 1, packet.payload.len());

        Ok(())
    }
}
