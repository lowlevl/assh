use std::{io, num::NonZeroU32, pin::Pin, task};

use assh::{Pipe, side::Side};
use ssh_packet::connect;

use crate::channel::Channel;

pub struct Write<'s, IO: Pipe, S: Side> {
    channel: &'s Channel<'s, IO, S>,
    stream_id: Option<NonZeroU32>,

    buffer: Vec<u8>,
}

impl<'s, IO: Pipe, S: Side> Write<'s, IO, S> {
    pub fn new(channel: &'s Channel<'s, IO, S>, stream_id: Option<NonZeroU32>) -> Self {
        Self {
            channel,
            stream_id,

            buffer: Default::default(),
        }
    }

    fn feed_data(&mut self) {
        let data = std::mem::take(&mut self.buffer).into();

        match self.stream_id {
            Some(data_type) => self.channel.mux.feed(&connect::ChannelExtendedData {
                recipient_channel: self.channel.id.remote(),
                data_type,
                data,
            }),
            None => self.channel.mux.feed(&connect::ChannelData {
                recipient_channel: self.channel.id.remote(),
                data,
            }),
        }
    }
}

impl<IO: Pipe, S: Side> futures::AsyncWrite for Write<'_, IO, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let _span = tracing::debug_span!(
            "io::Write",
            channel = self.channel.id.local(),
            stream = self.stream_id
        )
        .entered();

        futures::ready!(self.channel.poll(cx))
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        let writable = buf
            .len()
            .min(self.channel.remote_maxpack as usize - self.buffer.len());
        if writable == 0 {
            self.feed_data();

            cx.waker().wake_by_ref();
            return task::Poll::Pending;
        }

        let reserved =
            futures::ready!(self.channel.remote_window.poll_reserve(cx, writable as u32)) as usize;
        self.buffer.extend_from_slice(&buf[..reserved]);

        task::Poll::Ready(Ok(reserved))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let _span = tracing::debug_span!(
            "io::Write",
            channel = self.channel.id.local(),
            stream = self.stream_id
        )
        .entered();

        if !self.buffer.is_empty() {
            self.feed_data();
        }

        self.channel
            .mux
            .poll_flush(cx)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
