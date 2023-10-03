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
    transport: TransportPair,
    timeout: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    pub fn new(stream: BufReader<S>, transport: TransportPair, timeout: Duration) -> Self {
        Self {
            inner: stream,
            transport,
            timeout,
        }
    }

    pub fn with_transport(&mut self, transport: TransportPair) {
        self.transport = transport;
    }

    pub async fn recv<T>(&mut self) -> Result<T>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian + Debug,
    {
        let packet = Packet::from_async_reader(&mut self.inner, &self.transport)
            .timeout(self.timeout)
            .await??;

        let message = packet.decrypt(&mut self.transport)?;

        tracing::trace!("<- {message:?}");

        Ok(message)
    }

    pub async fn send<T>(&mut self, message: &T) -> Result<()>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian + Debug,
    {
        let packet = Packet::encrypt(message, &mut self.transport)?;

        packet
            .to_async_writer(&mut self.inner)
            .timeout(self.timeout)
            .await??;

        tracing::trace!("-> {message:?}",);

        Ok(())
    }

    pub fn should_rekey(&self) -> bool {
        self.transport.secret.is_empty() || self.transport.tx.seq > REKEY_THRESHOLD
    }
}
