//! The SSH _global requests_.

use assh::{side::Side, Pipe};
use futures::SinkExt;
use ssh_packet::{connect, IntoPacket};

use super::Connect;
use crate::Result;

// TODO: Drop implementation ?

// /// The outcome to a sent _global request_.
// #[derive(Debug)]
// pub enum GlobalRequestOutcome {
//     /// _Accepted_ global request.
//     Accepted,

//     /// _Accepted_ global request, with a bound port.
//     AcceptedPort(u32),

//     /// _Rejected_ the global request.
//     Rejected,
// }

/// A received _global request_.
pub struct GlobalRequest<'r, IO: Pipe, S: Side> {
    connect: &'r Connect<IO, S>,
    inner: connect::GlobalRequest,
}

impl<'r, IO: Pipe, S: Side> GlobalRequest<'r, IO, S> {
    pub(super) fn new(connect: &'r Connect<IO, S>, inner: connect::GlobalRequest) -> Self {
        Self { connect, inner }
    }

    /// Access the _context_ of the global request.
    pub fn cx(&self) -> &connect::GlobalRequestContext {
        &self.inner.context
    }

    /// Accept the global request.
    pub async fn accept(self, bound_port: u32) -> Result<()> {
        if *self.inner.want_reply {
            let packet = match self.inner.context {
                connect::GlobalRequestContext::TcpipForward { bind_port: 0, .. } => {
                    connect::ForwardingSuccess { bound_port }.into_packet()
                }
                _ => connect::RequestSuccess.into_packet(),
            };

            self.connect.poller.lock().await.send(packet).await?;
        }

        Ok(())
    }

    /// Reject the global request.
    pub async fn reject(self) -> Result<()> {
        if *self.inner.want_reply {
            self.connect
                .poller
                .lock()
                .await
                .send(connect::RequestFailure.into_packet())
                .await?;
        }

        Ok(())
    }
}
