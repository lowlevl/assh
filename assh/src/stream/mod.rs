//! Primitives to manipulate binary data to extract and encode
//! messages from/to a [`Pipe`] stream.

use futures::{AsyncBufReadExt, AsyncWriteExt};
use ssh_packet::IntoPacket;

use crate::{Pipe, Result};

pub mod algorithm;

mod iocounter;
use iocounter::IoCounter;

mod transport;
pub use transport::Transport;

#[doc(no_inline)]
pub use ssh_packet::Packet;

/// Re-key after 1GiB of exchanged data as recommended per the RFC.
const REKEY_BYTES_THRESHOLD: usize = 0x40000000;

/// A wrapper around a [`Pipe`] to interface with to the SSH binary protocol.
pub struct Stream<S> {
    inner: IoCounter<S>,

    /// The pair of transport algorithms and keys computed from the key exchange.
    transport: Transport,

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
    pub fn new(stream: S) -> Self {
        Self {
            inner: IoCounter::new(stream),
            transport: Default::default(),
            session: None,
            txseq: 0,
            rxseq: 0,
            buffer: None,
        }
    }

    pub fn should_rekey(&self) -> bool {
        self.session.is_none() || self.inner.count() > REKEY_BYTES_THRESHOLD
    }

    pub fn set_transport(&mut self, transport: Transport) {
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
                let data = self.transport.rx.rx(self.rxseq, &mut self.inner).await?;

                tracing::trace!(
                    "<~- #{}: ^{:#x} ({} bytes)",
                    self.rxseq,
                    data[0],
                    data.len(),
                );

                self.rxseq = self.rxseq.wrapping_add(1);

                Ok(Packet(data))
            }
        }
    }

    /// Encrypt and send a _packet_ to the peer.
    pub async fn send(&mut self, packet: impl IntoPacket) -> Result<()> {
        let data = packet.into_packet();

        self.transport
            .tx
            .tx(self.txseq, &data, &mut self.inner)
            .await?;
        self.inner.flush().await?;

        tracing::trace!(
            "-~> #{}: ^{:#x} ({} bytes)",
            self.txseq,
            data[0],
            data.len(),
        );

        self.txseq = self.txseq.wrapping_add(1);

        Ok(())
    }
}
