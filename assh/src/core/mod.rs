//! Primitives to manipulate binary data to extract and encode
//! messages from/to a [`Pipe`] stream.

use std::{
    pin::Pin,
    task,
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use futures::{AsyncBufReadExt, AsyncWrite, StreamExt};
use ssh_packet::{Packet, binrw::meta::WriteMagic};

use crate::{Error, Pipe, Result};

mod counter;
use counter::Counter;

pub mod algorithm;

pub mod rx;
pub mod tx;

const LEN_FIELD_SIZE: usize = std::mem::size_of::<u32>();
const PADLEN_FIELD_SIZE: usize = std::mem::size_of::<u8>();

/// Per RFC4253, all implementations MUST be able to process packets
/// with an uncompressed payload length of 32768 bytes or less.
const PAYLOAD_MAX_LEN: usize = 32768;

/// Per RFC4253, all implementations MUST be able to process [...]
/// a total packet size of 35000 bytes or less.
const PACKET_MAX_SIZE: usize = 35000;

/// Per RFC4253, the minimum size of a packet is 16
/// (or the cipher block size, whichever is larger).
///
/// NOTE: OpenSSH produces 12 bytes packets with `3des-cbc`, so this is the value.
const PACKET_MIN_SIZE: usize = 12;

/// Per RFC4253, implementations SHOULD decrypt the length after receiving
/// the first 8 (or cipher block size, whichever is larger) bytes of a packet.
const PACKET_MIN_READ: usize = 8;

/// A wrapper around a [`Pipe`] to interface with to the SSH binary protocol.
pub struct Core<IO> {
    inner: Counter<IO>,

    rxtransport: rx::Transport,
    /// FIXME: remove
    rxbuf: Option<Packet>,
    rxstate: rx::Reader,
    rxseq: u32,

    txtransport: tx::Transport,
    txstate: Bytes,
    txseq: u32,

    /// The session identifier derived from the first key exchange.
    session: Option<Vec<u8>>,

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
    pub fn new(inner: IO, serverside: bool) -> Self {
        Self {
            inner: Counter::new(inner),
            rxtransport: Default::default(),
            rxbuf: Default::default(),
            rxstate: Default::default(),
            rxseq: 0,
            txtransport: Default::default(),
            txstate: Default::default(),
            txseq: 0,
            session: Default::default(),
            rekeyed_at: Instant::now(),
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

    pub fn set_transport(&mut self, rx: rx::Transport, tx: tx::Transport) {
        self.rxtransport = rx;
        self.txtransport = tx;

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
        //! FIXME: remove

        let packet = self.recv().await?;

        Ok(self.rxbuf.insert(packet))
    }

    /// Receive and decrypt a _packet_ from the peer.
    pub async fn recv(&mut self) -> Result<Packet> {
        //! FIXME: remove

        match self.rxbuf.take() {
            Some(packet) => Ok(packet),
            None => {
                let data = self
                    .next()
                    .await
                    .ok_or(crate::Error::Io(std::io::ErrorKind::UnexpectedEof.into()))??;

                Ok(Packet(data.to_vec()))
            }
        }
    }
}

impl<IO: Pipe> futures::Stream for Core<IO> {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Self::Item>> {
        let this = &mut *self;

        if this.rxstate.len() == 0 {
            this.rxstate.grow(this.rxtransport.initial_block());
        }

        let data = loop {
            let eof = futures::ready!(this.rxstate.poll_fill(cx, &mut this.inner))?;
            if eof {
                return task::Poll::Ready(None);
            }

            // If we've just read the first block, we need to decrypt the length
            if this.rxstate.len() == this.rxtransport.initial_block() {
                let len = this.rxtransport.decrypt_length(this.rxstate.get_mut())?;

                // If the length differs from the current length, we need more data
                if this.rxstate.len() != len {
                    this.rxstate.grow(len);

                    continue;
                }
            }

            let buf = std::mem::take(&mut this.rxstate).into_inner();
            break this
                .rxtransport
                .decrypt(this.rxseq, buf, this.authenticated)?;
        };

        tracing::trace!(
            "<~- #{}: ^{:#x} ({} bytes)",
            this.rxseq,
            data[0],
            data.len(),
        );

        this.rxseq = this.rxseq.wrapping_add(1);

        // We are the client, and just received a `SSH_MSG_USERAUTH_SUCCESS` message,
        // which means we can start delayed compression from the next message.
        if !this.serverside && data[0] == ssh_packet::userauth::Success::MAGIC {
            this.authenticated = true;
        }

        task::Poll::Ready(Some(Ok(data)))
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

        debug_assert!(
            this.txstate.is_empty(),
            "start_send() got called while data's still pending"
        );

        tracing::trace!(
            "-~> #{}: ^{:#x} ({} bytes)",
            this.txseq,
            data[0],
            data.len(),
        );

        this.txstate = this
            .txtransport
            .encrypt(this.txseq, data, this.authenticated)?;

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
        let this = &mut *self;

        while !this.txstate.is_empty() {
            let n = futures::ready!(Pin::new(&mut this.inner).poll_write(cx, &this.txstate))?;
            if n == 0 {
                return task::Poll::Ready(Err(Error::Io(std::io::ErrorKind::WriteZero.into())));
            }

            this.txstate.advance(n);
        }

        Pin::new(&mut this.inner).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        futures::ready!(self.as_mut().poll_flush(cx))?;

        Pin::new(&mut self.inner).poll_close(cx).map_err(Into::into)
    }
}
