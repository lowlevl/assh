//! The SSH _global requests_.

use assh::{side::Side, Pipe};
use futures::SinkExt;
use ssh_packet::{connect, IntoPacket};

use super::Connect;
use crate::Result;

// TODO: Drop implementation ?

/// The outcome to a sent _global request_.
#[derive(Debug)]
pub enum GlobalRequestOutcome {
    /// _Accepted_ global request.
    Accepted,

    /// _Accepted_ global request, with a bound port.
    AcceptedPort(u32),

    /// _Rejected_ the global request.
    Rejected,
}

/// A received _global request_.
pub struct GlobalRequest<'a, IO: Pipe, S: Side>(&'a Connect<IO, S>, connect::GlobalRequest);

impl<'a, IO: Pipe, S: Side> GlobalRequest<'a, IO, S> {
    pub(super) fn new(connect: &'a Connect<IO, S>, cx: connect::GlobalRequest) -> Self {
        Self(connect, cx)
    }

    /// Access the _context_ of the global request.
    pub fn cx(&self) -> &connect::GlobalRequestContext {
        &self.1.context
    }

    /// Accept the global request.
    pub async fn accept(self, bound_port: u32) -> Result<()> {
        if *self.1.want_reply {
            let packet = match self.1.context {
                connect::GlobalRequestContext::TcpipForward { bind_port: 0, .. } => {
                    connect::ForwardingSuccess { bound_port }.into_packet()
                }
                _ => connect::RequestSuccess.into_packet(),
            };

            self.0.poller.lock().await.send(packet).await?;
        }

        Ok(())
    }

    /// Reject the global request.
    pub async fn reject(self) -> Result<()> {
        if *self.1.want_reply {
            self.0
                .poller
                .lock()
                .await
                .send(connect::RequestFailure.into_packet())
                .await?;
        }

        Ok(())
    }
}
