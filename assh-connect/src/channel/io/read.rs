use std::{
    io::{self, Read as _},
    pin::Pin,
    task,
};

use flume::{
    r#async::{RecvStream, SendSink},
    Sender,
};
use futures::{SinkExt, StreamExt};
use ssh_packet::{connect, IntoPacket, Packet};

use super::super::LocalWindow;

// TODO: Handle pending messages for window on Drop

pub struct Read<'io> {
    remote_id: u32,

    receiver: RecvStream<'static, Vec<u8>>,
    sender: SendSink<'io, Packet>,
    window: &'io LocalWindow,

    buffer: io::Cursor<Vec<u8>>,
}

impl<'io> Read<'io> {
    pub fn new(
        remote_id: u32,
        sender: SendSink<'io, Packet>,
        window: &'io LocalWindow,
    ) -> (Self, Sender<Vec<u8>>) {
        let (tx, receiver) = flume::unbounded();

        (
            Self {
                remote_id,

                receiver: receiver.into_stream(),
                sender,
                window,

                buffer: Default::default(),
            },
            tx,
        )
    }

    fn is_empty(&self) -> bool {
        self.buffer.position() >= self.buffer.get_ref().len() as u64
    }
}

impl futures::AsyncRead for Read<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        if self.is_empty() {
            if let task::Poll::Ready(res) = self.sender.poll_ready_unpin(cx) {
                res.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                if let Some(bytes_to_add) = self.window.adjustable() {
                    let packet = connect::ChannelWindowAdjust {
                        recipient_channel: self.remote_id,
                        bytes_to_add,
                    }
                    .into_packet();

                    self.sender
                        .start_send_unpin(packet)
                        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                    tracing::debug!(
                        "Adjusted window size by `{}` for channel %{}",
                        bytes_to_add,
                        self.remote_id,
                    );
                }
            }

            if let Some(data) = futures::ready!(self.receiver.poll_next_unpin(cx)) {
                self.window.consume(data.len() as u32);
                self.buffer = io::Cursor::new(data);
            }
        }

        task::Poll::Ready(self.buffer.read(buf))
    }
}
