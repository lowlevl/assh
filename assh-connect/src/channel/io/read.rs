use std::{
    collections::VecDeque,
    io::{self, Read as _},
    num::NonZeroU32,
    pin::Pin,
    task,
};

use assh::{side::Side, Pipe};
use futures::{FutureExt, Sink, SinkExt};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{channel::Channel, interest::Interest};

pub struct Read<'a, IO: Pipe, S: Side> {
    channel: &'a Channel<'a, IO, S>,
    stream_id: Option<NonZeroU32>,

    receiver: flume::Receiver<Vec<u8>>,
    buffer: VecDeque<u8>,
}

impl<'a, IO: Pipe, S: Side> Read<'a, IO, S> {
    pub fn new(channel: &'a Channel<'a, IO, S>, stream_id: Option<NonZeroU32>) -> Self {
        let (sender, receiver) = flume::unbounded();

        channel.streams.insert(stream_id, sender);

        Self {
            channel,
            stream_id,

            receiver,
            buffer: Default::default(),
        }
    }

    fn adjust_window(
        &mut self,
        poller: &mut (impl Sink<Packet, Error = assh::Error> + Unpin),
    ) -> io::Result<()> {
        if let Some(bytes_to_add) = self.channel.local_window.adjustable() {
            let packet = connect::ChannelWindowAdjust {
                recipient_channel: self.channel.remote_id,
                bytes_to_add,
            }
            .into_packet();

            poller.start_send_unpin(packet).ok();

            tracing::debug!(
                "Adjusted window size by `{}` for channel #{}",
                bytes_to_add,
                self.channel.local_id,
            );
        }

        Ok(())
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

        if let task::Poll::Ready(mut poller) = self.channel.connect.poller.lock().poll_unpin(cx) {
            self.adjust_window(&mut *poller)?;
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
            Err(flume::TryRecvError::Empty) => match self.channel.poll_for(cx, &Interest::None) {
                task::Poll::Ready(Some(Err(err))) => {
                    task::Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, err)))
                }
                _ => task::Poll::Pending,
            },
        }
    }
}

impl<'a, IO: Pipe, S: Side> Drop for Read<'a, IO, S> {
    fn drop(&mut self) {
        self.channel.streams.remove(&self.stream_id);
    }
}
