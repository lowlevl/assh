use std::{
    collections::VecDeque,
    io::{self, Read as _},
    num::NonZeroU32,
    pin::Pin,
    task,
};

use assh::{side::Side, Pipe};
use ssh_packet::connect;

use crate::channel::Channel;

pub struct Read<'s, IO: Pipe, S: Side> {
    channel: &'s Channel<'s, IO, S>,
    stream_id: Option<NonZeroU32>,

    receiver: flume::Receiver<Vec<u8>>,
    buffer: VecDeque<u8>,
}

impl<'s, IO: Pipe, S: Side> Read<'s, IO, S> {
    pub fn new(channel: &'s Channel<'s, IO, S>, stream_id: Option<NonZeroU32>) -> Self {
        let (sender, receiver) = flume::unbounded();

        channel.streams.insert(stream_id, sender);

        Self {
            channel,
            stream_id,

            receiver,
            buffer: Default::default(),
        }
    }
}

impl<IO: Pipe, S: Side> futures::AsyncRead for Read<'_, IO, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        let _span = tracing::debug_span!(
            "io::Read",
            channel = self.channel.local_id,
            stream = self.stream_id
        )
        .entered();

        if let Some(bytes_to_add) = self.channel.local_window.adjustable() {
            tracing::debug!(
                "Adjusted window size by `{}` for channel #{}",
                bytes_to_add,
                self.channel.local_id,
            );

            self.channel.mux.feed(&connect::ChannelWindowAdjust {
                recipient_channel: self.channel.remote_id,
                bytes_to_add,
            });
        }

        if !self.buffer.is_empty() {
            return task::Poll::Ready(self.buffer.read(buf));
        }

        match self.receiver.try_recv() {
            Ok(data) => {
                self.buffer.extend(data.iter());
                self.channel.local_window.consume(data.len() as u32);

                tracing::trace!(
                    "Received data block for stream `{:?}` on channel #{} of size `{}`",
                    self.stream_id,
                    self.channel.local_id,
                    data.len()
                );

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Err(flume::TryRecvError::Disconnected) => task::Poll::Ready(Ok(0)),
            Err(flume::TryRecvError::Empty) => {
                futures::ready!(self.channel.poll(cx))
                    .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                task::Poll::Pending
            }
        }
    }
}

impl<'s, IO: Pipe, S: Side> Drop for Read<'s, IO, S> {
    fn drop(&mut self) {
        self.channel.streams.remove(&self.stream_id);
    }
}
