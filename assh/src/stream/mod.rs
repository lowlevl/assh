//! Primitives to manipulate binary data to extract and encode
//! messages from/to a [`Pipe`] stream.

use futures::{AsyncBufReadExt, AsyncWriteExt, FutureExt};
use futures_time::{future::FutureExt as _, time::Duration};
use ssh_packet::IntoPacket;

use crate::{algorithm, Pipe, Result};

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

    /// Poll the stream to detect whether data is immediately readable.
    pub async fn is_readable(&mut self) -> Result<bool> {
        futures::select_biased! {
            buf = self.inner.fill_buf().fuse() => {
                buf?;

                Ok(true)
            }
            _ = futures::future::ready(()).fuse() => {
                Ok(false)
            }
        }
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
                    Packet::from_reader(&mut self.inner, &mut self.transport.rx, self.rxseq)
                        .timeout(self.timeout)
                        .await??;

                tracing::trace!(
                    "<~- #{}: ^{:#x} ({} bytes)",
                    self.rxseq,
                    packet.payload[0],
                    packet.payload.len(),
                );

                self.rxseq = self.rxseq.wrapping_add(1);

                Ok(packet)
            }
        }
    }

    /// Encrypt and send a _packet_ to the peer.
    pub async fn send(&mut self, packet: impl IntoPacket) -> Result<()> {
        let packet = packet.into_packet();

        packet
            .to_writer(&mut self.inner, &mut self.transport.tx, self.txseq)
            .timeout(self.timeout)
            .await??;
        self.inner.flush().await?;

        tracing::trace!(
            "-~> #{}: ^{:#x} ({} bytes)",
            self.txseq,
            packet.payload[0],
            packet.payload.len(),
        );

        self.txseq = self.txseq.wrapping_add(1);

        Ok(())
    }
}
