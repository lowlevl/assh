//! The _global requests_ and responses.

use assh::{side::Side, Pipe};
use ssh_packet::connect;

use crate::{mux::Mux, Result};

#[doc(no_inline)]
pub use ssh_packet::connect::GlobalRequestContext;

// TODO: (compliance) Drop implementation ?

/// A response to a _global request_.
#[derive(Debug)]
pub enum Response {
    /// The request succeeded, with optionally a bound port.
    Success(Option<u32>),

    /// The request failed.
    Failure,
}

/// A received _global request_.
pub struct GlobalRequest<'r, IO: Pipe, S: Side> {
    mux: &'r Mux<IO, S>,
    inner: connect::GlobalRequest,
}

impl<'r, IO: Pipe, S: Side> GlobalRequest<'r, IO, S> {
    pub(super) fn new(mux: &'r Mux<IO, S>, inner: connect::GlobalRequest) -> Self {
        Self { mux, inner }
    }

    /// Access the _context_ of the global request.
    pub fn cx(&self) -> &connect::GlobalRequestContext {
        &self.inner.context
    }

    /// Accept the global request.
    pub async fn accept(self, bound_port: u32) -> Result<()> {
        if *self.inner.want_reply {
            match self.inner.context {
                connect::GlobalRequestContext::TcpipForward { bind_port: 0, .. } => {
                    self.mux
                        .send(&connect::ForwardingSuccess { bound_port })
                        .await?
                }
                _ => self.mux.send(&connect::RequestSuccess).await?,
            }
        }

        Ok(())
    }

    /// Reject the global request.
    pub async fn reject(self) -> Result<()> {
        if *self.inner.want_reply {
            self.mux.send(&connect::RequestFailure).await?;
        }

        Ok(())
    }
}
