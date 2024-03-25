use ssh_packet::connect;

use super::{Channel, Msg};

pub struct Stream<'a> {
    pub channel: &'a Channel,
    pub ext: Option<connect::ChannelExtendedDataType>,
}

impl futures::AsyncRead for Stream<'_> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }
}

impl futures::AsyncWrite for Stream<'_> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) {
        self.channel
            .tx
            .send(Msg::ChannelEof(connect::ChannelEof {
                recipient_channel: self.channel.identifier,
            }))
            .inspect_err(|err| {
                tracing::error!(
                    "Unable to send the closing message for channel #{}: {err}",
                    self.channel.identifier
                )
            });
    }
}
