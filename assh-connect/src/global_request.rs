//! The _global requests_ and responses.

use assh::{side::Side, Pipe};
use ssh_packet::connect;

use crate::{mux::Mux, Result};

#[doc(no_inline)]
pub use ssh_packet::connect::GlobalRequestContext;

/// A response to a _global request_.
#[derive(Debug)]
pub enum Response {
    /// The request succeeded, with optionally a bound port.
    Success(Option<u32>),

    /// The request failed.
    Failure,
}

/// A received _global request_.
pub struct GlobalRequest<'s, IO: Pipe, S: Side> {
    mux: &'s Mux<IO, S>,
    inner: Option<connect::GlobalRequest>,
}

impl<'s, IO: Pipe, S: Side> GlobalRequest<'s, IO, S> {
    pub(super) fn new(mux: &'s Mux<IO, S>, inner: connect::GlobalRequest) -> Self {
        Self {
            mux,
            inner: Some(inner),
        }
    }

    /// Accept the global request.
    pub async fn accept(mut self, bound_port: u32) -> Result<()> {
        let inner = self
            .inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        if *inner.want_reply {
            match inner.context {
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

    pub(crate) fn rejected(mux: &Mux<IO, S>) {
        mux.feed(&connect::RequestFailure);
    }

    /// Reject the global request.
    pub async fn reject(mut self) -> Result<()> {
        let inner = self
            .inner
            .take()
            .expect("Inner value has been dropped before the outer structure");

        if *inner.want_reply {
            Self::rejected(self.mux);
            self.mux.flush().await?;
        }

        Ok(())
    }

    /// Access the _context_ of the global request.
    pub fn cx(&self) -> &connect::GlobalRequestContext {
        &self
            .inner
            .as_ref()
            .expect("Inner value has been dropped before the outer structure")
            .context
    }
}

impl<'s, IO: Pipe, S: Side> Drop for GlobalRequest<'s, IO, S> {
    fn drop(&mut self) {
        if matches!(&self.inner, Some(inner) if *inner.want_reply) {
            Self::rejected(self.mux);
        }
    }
}
