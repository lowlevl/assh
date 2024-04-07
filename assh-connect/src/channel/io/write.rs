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
        let window_size = self.channel.peer_window_size.load(Ordering::Acquire);
        let writable = self
            .channel
            .peer_maximum_packet_size
            .min(window_size)
            .min(buf.len() as u32) as usize;

        if writable == 0 {
            cx.waker().wake_by_ref();
            return task::Poll::Pending;
        }

        let data = buf[..writable].to_vec().into();
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
            .sender
            .send(msg)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
        self.channel
            .peer_window_size
            .fetch_sub(writable as u32, Ordering::Release);

        task::Poll::Ready(Ok(writable))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        task::Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.channel
            .sender
            .send(Msg::Eof(connect::ChannelEof {
                recipient_channel: self.channel.recipient_channel,
            }))
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        task::Poll::Ready(Ok(()))
    }
}
