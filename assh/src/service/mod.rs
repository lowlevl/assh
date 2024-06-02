//! Service handling facilities on [`session::Session`].

#[cfg(doc)]
use crate::session;

mod handler;
pub use handler::{handle, Handler};

mod request;
pub use request::{request, Request};
