//! Primitives to manipulate binary data to extract and encode
//! messages from/to a [`Pipe`] stream.

use std::{
    pin::Pin,
    task,
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use futures::{AsyncBufReadExt, AsyncWrite};
use ssh_packet::{Packet, binrw::meta::WriteMagic};

use crate::{Pipe, Result};

mod iocounter;
use iocounter::IoCounter;

mod transport;
pub use transport::Transport;

pub mod algorithm;

/// A wrapper around a [`Pipe`] to interface with to the SSH binary protocol.
pub struct Core<IO> {
    inner: IoCounter<IO>,

    /// The transport states from the key-exchange (keys, algorithms).
    transport: Transport,

    /// The session identifier derived from the first key exchange.
    session: Option<Vec<u8>>,

    txbuf: Option<Bytes>,
    rxbuf: Option<Packet>,

    txseq: u32,
    rxseq: u32,

    /// The last time encryption states & keys were rotated.
    rekeyed_at: Instant,

    /// Whether we are the server-side of this session.
    serverside: bool,

    /// Whether the server-side has sent `SSH_MSG_USERAUTH_SUCCESS`.
    authenticated: bool,
}

impl<IO> Core<IO>
where
    IO: Pipe,
{
    pub fn new(pipe: IO, serverside: bool) -> Self {
        Self {
            inner: IoCounter::new(pipe),
            transport: Default::default(),
            session: None,
            txbuf: None,
            rxbuf: None,
            rekeyed_at: Instant::now(),
            txseq: 0,
            rxseq: 0,
            serverside,
            authenticated: false,
        }
    }

    pub fn rekeyable(&self) -> bool {
        //! Per RFC 4253, it is RECOMMENDED that the keys be changed after each gigabyte of
        //! transmitted data or after each hour of connection time, whichever comes sooner.

        const REKEY_BYTES_THRESHOLD: usize = 0x40000000;

        self.session.is_none()
            || self.inner.count() >= REKEY_BYTES_THRESHOLD
            || self.rekeyed_at.elapsed() >= Duration::from_hours(1)
    }

    pub fn set_transport(&mut self, transport: Transport) {
        self.transport = transport;

        // Reset I/O counter and set last rekey to this instant.
        self.inner.reset();
        self.rekeyed_at = Instant::now();
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

        Ok(self.rxbuf.insert(packet))
    }

    /// Receive and decrypt a _packet_ from the peer.
    pub async fn recv(&mut self) -> Result<Packet> {
        match self.rxbuf.take() {
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
}

impl<IO: Pipe> futures::Stream for Core<IO> {
    type Item = ();

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Self::Item>> {
        todo!()
    }
}

impl<IO: Pipe> futures::Sink<&[u8]> for Core<IO> {
    type Error = crate::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, data: &[u8]) -> Result<(), Self::Error> {
        let this = &mut *self;

        tracing::trace!(
            "-~> #{}: ^{:#x} ({} bytes)",
            this.txseq,
            data[0],
            data.len(),
        );

        let encrypted = this
            .transport
            .tx
            .write(this.txseq, data, this.authenticated)?;

        this.txbuf = Some(encrypted);
        this.txseq = this.txseq.wrapping_add(1);

        // We are the server, and just sent a `SSH_MSG_USERAUTH_SUCCESS` message,
        // which means we can start delayed compression from the next message.
        if this.serverside && data[0] == ssh_packet::userauth::Success::MAGIC {
            this.authenticated = true;
        }

        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        let txbuf = self.txbuf.take();

        match txbuf {
            None => Pin::new(&mut self.inner).poll_flush(cx).map_err(Into::into),
            Some(mut data) => {
                let written =
                    futures::ready!(std::pin::Pin::new(&mut self.inner).poll_write(cx, &data))?;

                data.advance(written);
                if !data.is_empty() {
                    self.txbuf = Some(data);
                } else {
                    // This is equal to `txbuf = None`,
                    // so next poll we'll be flushing the Sink
                }

                // FIXME: is this the way to do it, or if we should use a loop {}
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        futures::ready!(self.as_mut().poll_flush(cx))?;

        Pin::new(&mut self.inner).poll_close(cx).map_err(Into::into)
    }
}
