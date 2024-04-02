use std::{io, pin::Pin, sync::atomic::Ordering, task};

use ssh_packet::connect;

use super::{Channel, Msg};

pub struct Write<'a> {
    channel: &'a Channel,
    ext: Option<connect::ChannelExtendedDataType>,
}

impl<'a> Write<'a> {
    pub fn new(channel: &'a Channel, ext: Option<connect::ChannelExtendedDataType>) -> Self {
        Self { channel, ext }
    }
}

impl futures::AsyncWrite for Write<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let window_size = self.channel.window_size.load(Ordering::Acquire);
        let writable = self
            .channel
            .maximum_packet_size
            .min(window_size)
            .min(buf.len() as u32) as usize;

        if writable == 0 {
            self.channel.window_size.fetch_add(0, Ordering::Release);

            cx.waker().wake_by_ref();
            return task::Poll::Pending;
        }

        let data = buf[..writable].to_vec().into();
        let msg = match self.ext {
            None => Msg::Data(connect::ChannelData {
                recipient_channel: self.channel.identifier,
                data,
            }),
            Some(ext) => Msg::ExtendedData(connect::ChannelExtendedData {
                recipient_channel: self.channel.identifier,
                data_type: ext,
                data,
            }),
        };

        match self.channel.sender.try_send(msg) {
            Ok(_) => {
                self.channel
                    .window_size
                    .fetch_sub(writable as u32, Ordering::Release);

                task::Poll::Ready(Ok(writable))
            }
            Err(flume::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Err(flume::TrySendError::Disconnected(_)) => task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Session disconnected before packet could be sent",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        task::Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        match self.channel.sender.try_send(Msg::Eof(connect::ChannelEof {
            recipient_channel: self.channel.identifier,
        })) {
            Ok(_) => task::Poll::Ready(Ok(())),
            Err(flume::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            Err(flume::TrySendError::Disconnected(_)) => task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Session disconnected before EOF could be sent",
            ))),
        }
    }
}
