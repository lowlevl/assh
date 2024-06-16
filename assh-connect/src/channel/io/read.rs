use std::{
    io::{self, Read as _},
    pin::Pin,
    sync::Arc,
    task,
};

use flume::{r#async::RecvStream, Sender};
use futures::StreamExt;

use super::LocalWindow;

// TODO: Handle pending messages for window on Drop

pub struct Read {
    receiver: RecvStream<'static, Vec<u8>>,
    window: Arc<LocalWindow>,

    buffer: io::Cursor<Vec<u8>>,
}

impl Read {
    pub fn new(window: Arc<LocalWindow>) -> (Self, Sender<Vec<u8>>) {
        let (sender, receiver) = flume::bounded(1);

        (
            Self {
                window,
                receiver: receiver.into_stream(),
                buffer: Default::default(),
            },
            sender,
        )
    }
}

impl futures::AsyncRead for Read {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        if self.buffer.position() >= self.buffer.get_ref().len() as u64 {
            self.buffer = io::Cursor::new(
                futures::ready!(self.receiver.poll_next_unpin(cx)).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "The channel has been disconnected",
                    )
                })?,
            );
        }

        let read = self.buffer.read(buf)?;
        self.window.consume(read as u32);

        task::Poll::Ready(Ok(read))
    }
}
