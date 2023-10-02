#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::unwrap_used, clippy::unimplemented)]

mod error;
pub use error::{Error, Result};

mod stream;
mod transport;

pub mod server;
