use std::fmt::Debug;

use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::{future::FutureExt, time::Duration};
use ssh_packet::{
    binrw::{
        meta::{ReadEndian, WriteEndian},
        BinRead, BinWrite,
    },
    Packet,
};

use crate::{transport::TransportPair, Result};

/// After 2 ^ 28 packets, initiate a rekey as recommended in the RFC.
pub const REKEY_THRESHOLD: u32 = 0x10000000;

// TODO: Rekey after 1GiB

pub struct Stream<S> {
    inner: BufReader<S>,
    timeout: Duration,
    transport: TransportPair,

    /// The session identifier derived from the first key exchange.
    session: Option<Vec<u8>>,

    /// Sequence numbers for the `tx` side.
    txseq: u32,
    /// Sequence numbers for the `rx` side.
    rxseq: u32,

    /// A packet buffer to enable `try_recv` method to function.
    buffer: Option<Packet>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    pub fn new(stream: BufReader<S>, transport: TransportPair, timeout: Duration) -> Self {
        Self {
            inner: stream,
            timeout,
            session: None,
            transport,
            txseq: 0,
            rxseq: 0,
            buffer: None,
        }
    }

    pub fn with_session(&mut self, session: &[u8]) -> &mut Vec<u8> {
        self.session.get_or_insert_with(|| session.to_vec())
    }

    pub fn with_transport(&mut self, transport: TransportPair) {
        self.transport = transport;
    }

    async fn packet(&mut self) -> Result<Packet> {
        let packet = Packet::from_async_reader(&mut self.inner, &mut self.transport.rx, self.rxseq)
            .timeout(self.timeout)
            .await??;

        self.rxseq = self.rxseq.wrapping_add(1);

        Ok(packet)
    }

    /// Read a packet from the connected peer, process it and
    /// read the underlying message in a non-blocking way,
    /// and store the packet if deserialization failed.
    pub async fn try_recv<T>(&mut self) -> Result<Option<T>>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian + Debug,
    {
        let packet = match self.buffer.take() {
            Some(packet) => packet,
            None if !self.inner.buffer().is_empty() => self.packet().await?,
            None => return Ok(None),
        };
        let message = packet.read().ok();

        if message.is_none() {
            self.buffer = Some(packet);
        }

        tracing::trace!("<-({})? {message:?}", self.rxseq - 1);

        Ok(message)
    }

    /// Read a packet from the connected peer, process it and
    /// read the underlying message.
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

    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian + Debug,
    {
        let packet = Packet::write(message)?;

        packet
            .to_async_writer(&mut self.inner, &mut self.transport.tx, self.txseq)
            .timeout(self.timeout)
            .await??;

        self.txseq = self.txseq.wrapping_add(1);

        tracing::trace!("({})-> {message:?}", self.txseq - 1);

        Ok(())
    }

    pub fn should_rekey(&self) -> bool {
        self.session.is_none() || self.txseq > REKEY_THRESHOLD
    }
}
