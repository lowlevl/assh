//! Primitives to manipulate binary data to extract and encode
//! messages from/to a [`Pipe`] stream.

use futures::{AsyncBufReadExt, AsyncWriteExt};
use ssh_packet::{IntoPacket, Packet, binrw::meta::WriteMagic};

use crate::{Pipe, Result};

pub mod algorithm;

mod iocounter;
use iocounter::IoCounter;

mod transport;
pub use transport::Transport;

/// A wrapper around a [`Pipe`] to interface with to the SSH binary protocol.
pub struct Stream<S> {
    inner: IoCounter<S>,

    /// The pair of transport algorithms and keys computed from the key exchange.
    transport: Transport,

    /// The session identifier derived from the first key exchange.
    session: Option<Vec<u8>>,

    /// Whether we are the server-side of this session.
    serverside: bool,

    /// Whether the server-side has sent `SSH_MSG_USERAUTH_SUCCESS`.
    authenticated: bool,

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
    pub fn new(stream: S, serverside: bool) -> Self {
        Self {
            inner: IoCounter::new(stream),
            transport: Default::default(),
            session: None,
            serverside,
            authenticated: false,
            txseq: 0,
            rxseq: 0,
            buffer: None,
        }
    }

    pub fn should_rekey(&self) -> bool {
        // TODO (security): re-key after an hour without rekeying.

        /// Per RFC 4253, it is RECOMMENDED that the keys be changed after each gigabyte of
        /// transmitted data or after each hour of connection time, whichever comes sooner.
        const REKEY_BYTES_THRESHOLD: usize = 0x40000000;

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
                let data = self
                    .transport
                    .rx
                    .read(self.rxseq, &mut self.inner, self.authenticated)
                    .await?;

                // We are the client, and just received a `SSH_MSG_USERAUTH_SUCCESS` message,
                // which means we can start delayed compression from the next message.
                if !self.serverside && data[0] == ssh_packet::userauth::Success::MAGIC {
                    self.authenticated = true;
                }

                tracing::trace!(
                    "<~- #{}: ^{:#x} ({} bytes)",
                    self.rxseq,
                    data[0],
                    data.len(),
                );

                self.rxseq = self.rxseq.wrapping_add(1);

                Ok(Packet(data.to_vec()))
            }
        }
    }

    /// Encrypt and send a _packet_ to the peer.
    pub async fn send(&mut self, packet: impl IntoPacket) -> Result<()> {
        let data = packet.into_packet();

        self.transport
            .tx
            .write(self.txseq, &data, &mut self.inner, self.authenticated)
            .await?;
        self.inner.flush().await?;

        // We are the server, and just sent a `SSH_MSG_USERAUTH_SUCCESS` message,
        // which means we can start delayed compression from the next message.
        if self.serverside && data[0] == ssh_packet::userauth::Success::MAGIC {
            self.authenticated = true;
        }

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
