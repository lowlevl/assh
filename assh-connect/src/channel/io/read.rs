use std::{
    io::{self, Read as _},
    num::NonZeroU32,
    pin::Pin,
    task,
};

use flume::r#async::SendSink;
use futures::SinkExt;
use ssh_packet::{connect, IntoPacket, Packet};

use super::super::Multiplexer;

pub struct Read<'io> {
    remote_id: u32,
    stream_id: Option<NonZeroU32>,

    mux: &'io Multiplexer,
    sender: SendSink<'io, Packet>,

    buffer: io::Cursor<Vec<u8>>,
}

impl<'io> Read<'io> {
    pub fn new(
        remote_id: u32,
        stream_id: Option<NonZeroU32>,
        mux: &'io Multiplexer,
        sender: SendSink<'io, Packet>,
    ) -> Self {
        Self {
            remote_id,
            stream_id,

            mux,
            sender,

            buffer: Default::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.buffer.position() >= self.buffer.get_ref().len() as u64
    }

    fn poll_adjust_window(&mut self, cx: &mut task::Context) -> io::Result<()> {
        if let task::Poll::Ready(res) = self.sender.poll_ready_unpin(cx) {
            res.map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

            if let Some(bytes_to_add) = self.mux.window().adjustable() {
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

        Ok(())
    }
}

impl futures::AsyncRead for Read<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        if self.is_empty() {
            self.poll_adjust_window(cx)?;

            self.buffer = io::Cursor::new(futures::ready!(self.mux.poll_data(cx, self.stream_id)));

            tracing::trace!(
                "Received data block for stream `{:?}` on channel %{} of size `{}`",
                self.stream_id,
                self.remote_id,
                self.buffer.get_ref().len()
            );
        }

        task::Poll::Ready(self.buffer.read(buf))
    }
}
