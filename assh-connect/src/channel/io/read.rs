use std::{
    io::{self, Read as _},
    num::NonZeroU32,
    pin::Pin,
    task,
};

use assh::{side::Side, Pipe};
use futures::{FutureExt, Sink, SinkExt};
use ssh_packet::{connect, IntoPacket, Packet};

use crate::{channel::Channel, connect::Interest};

pub struct Read<'a, IO: Pipe, S: Side> {
    channel: &'a Channel<'a, IO, S>,
    stream_id: Option<NonZeroU32>,

    buffer: io::Cursor<Vec<u8>>,
}

impl<'a, IO: Pipe, S: Side> Read<'a, IO, S> {
    pub fn new(channel: &'a Channel<'a, IO, S>, stream_id: Option<NonZeroU32>) -> Self {
        channel
            .connect
            .register(Interest::ChannelData(channel.local_id, stream_id));

        Self {
            channel,
            stream_id,

            buffer: Default::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.buffer.position() >= self.buffer.get_ref().len() as u64
    }

    fn poll_adjust_window(
        &mut self,
        poller: &mut (impl Sink<Packet, Error = assh::Error> + Unpin),
        cx: &mut task::Context,
    ) -> io::Result<()> {
        if let task::Poll::Ready(res) = poller.poll_ready_unpin(cx) {
            res.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

            if let Some(bytes_to_add) = self.channel.local_window.adjustable() {
                let packet = connect::ChannelWindowAdjust {
                    recipient_channel: self.channel.remote_id,
                    bytes_to_add,
                }
                .into_packet();

                poller
                    .start_send_unpin(packet)
                    .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                tracing::debug!(
                    "Adjusted window size by `{}` for channel {}:{}",
                    bytes_to_add,
                    self.channel.local_id,
                    self.channel.remote_id,
                );
            }
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
        if self.is_empty() {
            {
                let mut poller = futures::ready!(self.channel.connect.poller.lock().poll_unpin(cx));
                self.poll_adjust_window(&mut *poller, cx)?;
            }

            let polled = self.channel.poll_take(
                cx,
                &Interest::ChannelData(self.channel.local_id, self.stream_id),
            );
            if let Some(packet) = futures::ready!(polled) {
                let packet =
                    packet.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                let data = if self.stream_id.is_none() {
                    packet.to::<connect::ChannelData>().unwrap().data
                } else {
                    packet.to::<connect::ChannelExtendedData>().unwrap().data
                };

                self.buffer = io::Cursor::new(data.into_vec());
                self.channel
                    .local_window
                    .consume(self.buffer.get_ref().len() as u32);

                tracing::trace!(
                    "Received data block for stream `{:?}` on channel {}:{} of size `{}`",
                    self.stream_id,
                    self.channel.local_id,
                    self.channel.remote_id,
                    self.buffer.get_ref().len()
                );
            } else {
                tracing::trace!(
                    "End-of-file for stream `{:?}` on channel {}:{}",
                    self.stream_id,
                    self.channel.local_id,
                    self.channel.remote_id,
                );
            }
        }

        task::Poll::Ready(self.buffer.read(buf))
    }
}

impl<'a, IO: Pipe, S: Side> Drop for Read<'a, IO, S> {
    fn drop(&mut self) {
        self.channel.connect.unregister(&Interest::ChannelData(
            self.channel.local_id,
            self.stream_id,
        ));
    }
}
