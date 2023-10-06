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
    session: Option<Vec<u8>>,
    transport: TransportPair,

    /// Packets sequence numbers, (`rx`, `tx`).
    seq: (u32, u32),
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    pub fn new(stream: BufReader<S>, transport: TransportPair, timeout: Duration) -> Self {
        Self {
            inner: stream,
            timeout,
            session: None,
            transport,
            seq: (0, 0),
        }
    }

    pub fn with_session(&mut self, session: &[u8]) -> &mut Vec<u8> {
        self.session.get_or_insert_with(|| session.to_vec())
    }

    pub fn with_transport(&mut self, transport: TransportPair) {
        self.transport = transport;
    }

    pub async fn recv<T>(&mut self) -> Result<T>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian + Debug,
    {
        let packet = Packet::from_async_reader(&mut self.inner, &mut self.transport.rx, self.seq.0)
            .timeout(self.timeout)
            .await??;

        self.seq.0 = self.seq.0.wrapping_add(1);

        let message = packet.read()?;

        tracing::trace!("<-({}) {message:?}", self.seq.0 - 1);

        Ok(message)
    }

    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian + Debug,
    {
        let packet = Packet::write(message)?;

        packet
            .to_async_writer(&mut self.inner, &mut self.transport.tx, self.seq.1)
            .timeout(self.timeout)
            .await??;

        self.seq.1 = self.seq.1.wrapping_add(1);

        tracing::trace!("({})-> {message:?}", self.seq.1 - 1);

        Ok(())
    }

    pub fn should_rekey(&self) -> bool {
        self.session.is_none() || self.seq.1 > REKEY_THRESHOLD
    }
}
