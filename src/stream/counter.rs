use std::task::Poll;

use futures::io::{AsyncRead, AsyncWrite};

pub struct IoCounter<C> {
    inner: C,
    rx: usize,
    tx: usize,
}

impl<C> IoCounter<C> {
    pub fn new(inner: C) -> Self {
        IoCounter {
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

impl<C: AsyncRead + Unpin> AsyncRead for IoCounter<C> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(bytes)) = poll {
            self.rx += bytes;
        }

        poll
    }

    fn poll_read_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_read_vectored(cx, bufs)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for IoCounter<C> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(bytes)) = poll {
            self.tx += bytes;
        }

        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl<C> std::ops::Deref for IoCounter<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<C> std::ops::DerefMut for IoCounter<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
