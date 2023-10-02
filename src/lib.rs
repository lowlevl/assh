#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::unwrap_used)]

mod error;
pub use error::{Error, Result};

mod stream;
mod transport;

pub mod server;
