use std::{io, pin::Pin, sync::atomic::Ordering, task};

use super::{Channel, Msg};
use ssh_packet::connect;

pub struct Write<'a> {
    channel: &'a Channel,
    ext: Option<connect::ChannelExtendedDataType>,

    buffer: Vec<u8>,
}

impl<'a> Write<'a> {
    pub fn new(channel: &'a Channel, ext: Option<connect::ChannelExtendedDataType>) -> Self {
        Self {
            channel,
            ext,
            buffer: Vec::with_capacity(channel.peer_maximum_packet_size as usize),
        }
    }
}

impl futures::AsyncWrite for Write<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let size: usize = self.buffer.len();

        if size >= self.channel.peer_maximum_packet_size as usize {
            futures::ready!(self.as_mut().poll_flush(cx)?);
        }

        let writable = buf
            .len()
            .min(self.channel.peer_maximum_packet_size as usize - size);

        if writable > 0 {
            self.buffer.extend_from_slice(&buf[..writable]);

            task::Poll::Ready(Ok(writable))
        } else {
            cx.waker().wake_by_ref();
            task::Poll::Pending
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        if self.buffer.is_empty() {
            task::Poll::Ready(Ok(()))
        } else {
            let flushable = self
                .channel
                .peer_maximum_packet_size
                .min(self.channel.peer_window_size.load(Ordering::Acquire))
                .min(self.buffer.len() as u32) as usize;

            if flushable > 0 {
                let mut data = self.buffer.split_off(flushable);
                std::mem::swap(&mut data, &mut self.buffer);

                tracing::debug!(
                    "Flushing data of size {} bytes for channel %{}",
                    data.len(),
                    self.channel.recipient_channel
                );

                let data = data.into();
                let msg = match self.ext {
                    None => Msg::Data(connect::ChannelData {
                        recipient_channel: self.channel.recipient_channel,
                        data,
                    }),
                    Some(ext) => Msg::ExtendedData(connect::ChannelExtendedData {
                        recipient_channel: self.channel.recipient_channel,
                        data_type: ext,
                        data,
                    }),
                };

                self.channel
                    .peer_window_size
                    .fetch_sub(flushable as u32, Ordering::AcqRel);

                self.channel
                    .sender
                    .send(msg)
                    .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                task::Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        futures::ready!(self.as_mut().poll_flush(cx)?);

        self.channel
            .sender
            .send(Msg::Eof(connect::ChannelEof {
                recipient_channel: self.channel.recipient_channel,
            }))
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        task::Poll::Ready(Ok(()))
    }
}
