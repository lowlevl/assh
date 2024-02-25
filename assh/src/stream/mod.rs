//! Primitives to manipulate binary data to extract and encode
//! messages from/to an [`AsyncBufRead`] + [`AsyncWrite`] stream.

use std::fmt::Debug;

use futures::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use futures_time::{future::FutureExt, time::Duration};
use ssh_packet::{
    binrw::{
        meta::{ReadEndian, WriteEndian},
        BinRead, BinWrite,
    },
    Packet,
};

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

    /// A packet buffer for the `try_recv` method.
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

    async fn packet(&mut self) -> Result<Packet> {
        let packet = Packet::from_async_reader(&mut self.inner, &mut self.transport.rx, self.rxseq)
            .timeout(self.timeout)
            .await??;

        self.rxseq = self.rxseq.wrapping_add(1);

        Ok(packet)
    }

    /// Try to receive a _packet_ from the peer (if data is immediately available, returning `None` otherwise),
    /// storing the _packet_ and returning `None` if the deserialization failed.
    pub async fn try_recv<T>(&mut self) -> Result<Option<T>>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian + Debug,
    {
        let packet = match self.buffer.take() {
            Some(packet) => packet,
            None => {
                match self
                    .inner
                    .fill_buf()
                    .timeout(Duration::from_micros(1))
                    .await
                    .ok()
                    .transpose()?
                {
                    Some(buf) if !buf.is_empty() => self.packet().await?,
                    _ => return Ok(None),
                }
            }
        };

        match packet.read() {
            Ok(message) => {
                tracing::trace!("<-({})? {message:?}", self.rxseq - 1);

                Ok(Some(message))
            }
            _ => {
                self.buffer = Some(packet);

                Ok(None)
            }
        }
    }

    /// Receive a _packet_ from the peer, decrypt it and deserialize it as `T`.
    pub async fn recv<T>(&mut self) -> Result<T>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian + Debug,
    {
        let packet = match self.buffer.take() {
            Some(packet) => packet,
            None => self.packet().await?,
        };
        let message = packet.read()?;

        tracing::trace!("<-({}) {message:?}", self.rxseq - 1);

        Ok(message)
    }

    /// Send a _packet_ to the peer, by serializing and encrypting the `message`.
    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian + Debug,
    {
        let packet = Packet::write(message)?;

        packet
            .to_async_writer(&mut self.inner, &mut self.transport.tx, self.txseq)
            .timeout(self.timeout)
            .await??;
        self.inner.flush().await?;

        self.txseq = self.txseq.wrapping_add(1);

        tracing::trace!("({})-> {message:?}", self.txseq - 1);

        Ok(())
    }

    /// Returns whether the stream should be re-keyed.
    pub(crate) fn rekeyable(&self) -> bool {
        self.session.is_none() || self.inner.count() > REKEY_BYTES_THRESHOLD
    }
}
