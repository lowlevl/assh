#![doc = include_str!("../README.md")]
//! ## Supported algorithms
//!
//! #### Key-exchange:
//! see [`algorithm::Kex`].
//!
//! #### Encryption:
//!
//! see [`algorithm::Cipher`].
//!
//! #### MACs
//!
//! see [`algorithm::Hmac`].
//!
//! #### Compression:
//!
//! see [`algorithm::Compress`].

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::unwrap_used, clippy::unimplemented)]

mod stream;
mod transport;

mod error;
pub use error::{Error, Result};

pub use ssh_key::PrivateKey;
pub use ssh_packet::{Id, Message};

pub mod algorithm;
pub mod session;
