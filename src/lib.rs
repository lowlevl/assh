#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::unwrap_used, clippy::unimplemented)]

mod error;
pub use error::{Error, Result};

pub use ssh_key::PrivateKey;
pub use ssh_packet::{Id, Message};

mod stream;
mod transport;

pub mod algorithm;
pub mod server;
