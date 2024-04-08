use std::{io, pin::Pin, sync::atomic::Ordering, task};

use ssh_packet::connect;

use crate::{INITIAL_WINDOW_SIZE, MAXIMUM_PACKET_SIZE};

use super::{Channel, Msg};

pub struct Read<'a> {
    channel: &'a Channel,
    ext: Option<connect::ChannelExtendedDataType>,

    buffer: Option<(Msg, usize)>,
}

impl<'a> Read<'a> {
    pub fn new(channel: &'a Channel, ext: Option<connect::ChannelExtendedDataType>) -> Self {
        Self {
            channel,
            ext,
            buffer: None,
        }
    }
}

impl futures::AsyncRead for Read<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        // Replenish the window when reading.
        let window_size = self.channel.window_size.load(Ordering::Acquire);
        if window_size < MAXIMUM_PACKET_SIZE * 48 {
            let bytes_to_add = INITIAL_WINDOW_SIZE - window_size;

            self.channel
                .window_size
                .fetch_add(bytes_to_add, Ordering::AcqRel);

            self.channel
                .sender
                .send(Msg::WindowAdjust(connect::ChannelWindowAdjust {
                    recipient_channel: self.channel.recipient_channel,
                    bytes_to_add,
                }))
                .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

            tracing::debug!(
                "Added {bytes_to_add} to window for %{}",
                self.channel.recipient_channel
            );
        }

        let (msg, mut idx) = match self.buffer.take() {
            Some(buffer) => buffer,
            None => match self.channel.receiver.try_recv() {
                Ok(msg) => {
                    let size = match msg {
                        Msg::Data(connect::ChannelData { ref data, .. }) => data.len(),
                        Msg::ExtendedData(connect::ChannelExtendedData { ref data, .. }) => {
                            data.len()
                        }
                        _ => 0,
                    };

                    self.channel
                        .window_size
                        .fetch_sub(size as u32, Ordering::AcqRel);

                    (msg, 0)
                }
                Err(flume::TryRecvError::Empty) => {
                    cx.waker().wake_by_ref();
                    return task::Poll::Pending;
                }
                Err(flume::TryRecvError::Disconnected) => {
                    return task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Session disconnected before packet could be received",
                    )))
                }
            },
        };

        // Process received messages containing data, ignoring any other message.
        match (&msg, self.ext) {
            (Msg::Data(connect::ChannelData { data, .. }), None) => {
                let readable = buf.len().min(data.len() - idx);

                buf[..readable].copy_from_slice(&data[idx..idx + readable]);
                idx += readable;

                if idx != data.len() {
                    self.buffer = Some((msg, idx));
                }

                task::Poll::Ready(Ok(readable))
            }
            (
                Msg::ExtendedData(connect::ChannelExtendedData {
                    data,
                    data_type: ext,
                    ..
                }),
                Some(target),
            ) if *ext == target => {
                let readable = buf.len().min(data.len() - idx);

                buf[..readable].copy_from_slice(&data[idx..idx + readable]);
                idx += readable;

                if idx != data.len() {
                    self.buffer = Some((msg, idx));
                }

                task::Poll::Ready(Ok(readable))
            }
            (Msg::Eof { .. }, _) => task::Poll::Ready(Ok(0)),
            _ => {
                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
        }
    }
}
