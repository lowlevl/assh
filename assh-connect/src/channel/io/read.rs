use std::{io, pin::Pin, task};

use ssh_packet::connect;

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
        let (msg, mut idx) = match self.buffer.take() {
            Some(buffer) => buffer,
            None => match self.channel.receiver.try_recv() {
                Ok(msg) => (msg, 0),
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

        match (&msg, self.ext) {
            (Msg::Data(connect::ChannelData { data, .. }), None) => {
                let readable = buf.len().min(data.len() - idx);

                buf.copy_from_slice(&data[idx..idx + readable]);
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

                buf.copy_from_slice(&data[idx..idx + readable]);
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
