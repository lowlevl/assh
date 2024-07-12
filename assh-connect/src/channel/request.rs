use flume::Sender;
use ssh_packet::{
    connect::{self, ChannelRequest, ChannelRequestContext},
    IntoPacket, Packet,
};

/// A response to a channel request.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The request succeeded.
    Success,

    /// The request failed.
    Failure,
}

/// A channel request, either accepted by calling [`Self::accept`] or rejected by dropping it.
pub struct Request {
    remote_id: u32,
    outgoing: Sender<Packet>,
    inner: Option<connect::ChannelRequest>,
}

impl Request {
    pub(super) fn new(remote_id: u32, outgoing: Sender<Packet>, request: ChannelRequest) -> Self {
        Self {
            remote_id,
            outgoing,
            inner: Some(request),
        }
    }

    /// Access the context of the current channel request.
    pub fn cx(&self) -> &connect::ChannelRequestContext {
        self.inner
            .as_ref()
            .map(|request| &request.context)
            .expect("Request already dropped, aborting.")
    }

    /// Report the request as _accepted_ to the peer if it asked for a response.
    pub async fn accept(mut self) -> ChannelRequestContext {
        let request = self
            .inner
            .take()
            .expect("Request already dropped, aborting.");

        if *request.want_reply {
            self.outgoing
                .send_async(
                    connect::ChannelSuccess {
                        recipient_channel: self.remote_id,
                    }
                    .into_packet(),
                )
                .await
                .ok();
        }

        request.context
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if matches!(self.inner.take(), Some(ChannelRequest { want_reply, .. }) if *want_reply) {
            self.outgoing
                .try_send(
                    connect::ChannelFailure {
                        recipient_channel: self.remote_id,
                    }
                    .into_packet(),
                )
                .ok();
        }
    }
}
