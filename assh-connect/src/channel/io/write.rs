use std::{io, num::NonZeroU32, pin::Pin, task};

use assh::{side::Side, Pipe};
use futures::{FutureExt, SinkExt};
use ssh_packet::{connect, IntoPacket};

use crate::{channel::Channel, interest::Interest};

pub struct Write<'a, IO: Pipe, S: Side> {
    channel: &'a Channel<'a, IO, S>,
    stream_id: Option<NonZeroU32>,

    buffer: Vec<u8>,
}

impl<'a, IO: Pipe, S: Side> Write<'a, IO, S> {
    pub fn new(channel: &'a Channel<'a, IO, S>, stream_id: Option<NonZeroU32>) -> Self {
        Self {
            channel,
            stream_id,

            buffer: Default::default(),
        }
    }

    fn poll_send(&mut self, cx: &mut task::Context) -> task::Poll<io::Result<()>> {
        let mut sender = futures::ready!(self.channel.connect.poller.lock().poll_unpin(cx));

        let data = std::mem::take(&mut self.buffer).into();
        let packet = if let Some(data_type) = self.stream_id {
            connect::ChannelExtendedData {
                recipient_channel: self.channel.remote_id,
                data_type,
                data,
            }
            .into_packet()
        } else {
            connect::ChannelData {
                recipient_channel: self.channel.remote_id,
                data,
            }
            .into_packet()
        };

        sender.start_send_unpin(packet).ok();

        task::Poll::Ready(Ok(()))
    }
}

impl<IO: Pipe, S: Side> futures::AsyncWrite for Write<'_, IO, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        futures::ready!(self.channel.poll_for(cx, &Interest::None))
            .transpose()
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        let writable = buf
            .len()
            .min(self.channel.remote_maxpack as usize - self.buffer.len());
        if writable == 0 {
            futures::ready!(self.poll_send(cx))?;

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
        if !self.buffer.is_empty() {
            futures::ready!(self.poll_send(cx))?;
        }

        let mut sender = futures::ready!(self.channel.connect.poller.lock().poll_unpin(cx));
        sender
            .poll_flush_unpin(cx)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
