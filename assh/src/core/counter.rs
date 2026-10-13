use std::{io, pin::Pin, task};

use futures::io::{AsyncRead, AsyncWrite};

/// A simple wrapper for [`AsyncRead`] & [`AsyncWrite`]
/// which counts the number of bytes transfered.
pub struct Counter<IO> {
    inner: IO,

    rx: usize,
    tx: usize,
}

impl<IO> Counter<IO> {
    pub fn new(inner: IO) -> Self {
        Counter {
            inner,
            rx: 0,
            tx: 0,
        }
    }

    pub fn count(&self) -> usize {
        self.rx + self.tx
    }

    pub fn reset(&mut self) {
        self.rx = 0;
        self.tx = 0;
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Counter<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let task::Poll::Ready(Ok(bytes)) = poll {
            self.rx += bytes;
        }

        poll
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Counter<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let task::Poll::Ready(Ok(bytes)) = poll {
            self.tx += bytes;
        }

        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> task::Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);

        if let task::Poll::Ready(Ok(bytes)) = poll {
            self.tx += bytes;
        }

        poll
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl<IO> std::ops::Deref for Counter<IO> {
    type Target = IO;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<IO> std::ops::DerefMut for Counter<IO> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
