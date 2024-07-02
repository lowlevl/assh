use std::{io, num::NonZeroU32, pin::Pin, sync::Arc, task};

use flume::r#async::SendSink;
use futures::SinkExt;
use ssh_packet::{connect, IntoPacket, Packet};

use super::RemoteWindow;

pub struct Write {
    remote_id: u32,
    stream_id: Option<NonZeroU32>,

    sender: SendSink<'static, Packet>,
    window: Arc<RemoteWindow>,
    max_size: u32,

    buffer: Vec<u8>,
}

impl Write {
    pub fn new(
        remote_id: u32,
        stream_id: Option<NonZeroU32>,
        sender: SendSink<'static, Packet>,
        window: Arc<RemoteWindow>,
        max_size: u32,
    ) -> Self {
        Self {
            sender,
            window,
            max_size,

            remote_id,
            stream_id,

            buffer: Default::default(),
        }
    }
}

impl futures::AsyncWrite for Write {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        loop {
            let writable = buf.len().min(self.max_size as usize - self.buffer.len());
            if writable == 0 {
                futures::ready!(self.as_mut().poll_flush(cx))?;

                continue;
            }

            let reserved = futures::ready!(self.window.poll_reserve(cx, writable as u32)) as usize;
            self.buffer.extend_from_slice(&buf[..reserved]);

            break task::Poll::Ready(Ok(reserved));
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        if self.buffer.is_empty() {
            return task::Poll::Ready(Ok(()));
        }

        futures::ready!(self.sender.poll_ready_unpin(cx))
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        let packet = if let Some(data_type) = self.stream_id {
            connect::ChannelExtendedData {
                recipient_channel: self.remote_id,
                data_type,
                data: self.buffer.drain(..).collect::<Vec<_>>().into(),
            }
            .into_packet()
        } else {
            connect::ChannelData {
                recipient_channel: self.remote_id,
                data: self.buffer.drain(..).collect::<Vec<_>>().into(),
            }
            .into_packet()
        }
        .expect("Conversion to Packet shouldn't fail");

        self.sender
            .start_send_unpin(packet)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        task::Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
