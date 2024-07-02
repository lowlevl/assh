use std::{
    io::{self, Read as _},
    pin::Pin,
    sync::Arc,
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

pub struct Read<'a> {
    remote_id: u32,

    receiver: RecvStream<'static, Vec<u8>>,
    sender: SendSink<'a, Packet>,
    window: Arc<LocalWindow>,

    buffer: io::Cursor<Vec<u8>>,
}

impl<'a> Read<'a> {
    pub fn new(
        remote_id: u32,
        sender: SendSink<'a, Packet>,
        window: Arc<LocalWindow>,
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
}

impl futures::AsyncRead for Read<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        if self.buffer.position() >= self.buffer.get_ref().len() as u64 {
            if let task::Poll::Ready(res) = self.sender.poll_ready_unpin(cx) {
                res.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

                if let Some(bytes_to_add) = self.window.adjust() {
                    let packet = connect::ChannelWindowAdjust {
                        recipient_channel: self.remote_id,
                        bytes_to_add,
                    }
                    .into_packet()
                    .expect("Conversion to Packet shouldn't fail");

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

            self.buffer = io::Cursor::new(
                futures::ready!(self.receiver.poll_next_unpin(cx)).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "The channel has been disconnected",
                    )
                })?,
            );

            self.window.consume(self.buffer.get_ref().len() as u32);
        }

        task::Poll::Ready(self.buffer.read(buf))
    }
}
