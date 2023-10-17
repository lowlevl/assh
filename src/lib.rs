#![doc = include_str!("../README.md")]
//! ### Supported algorithms
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
#![warn(clippy::unwrap_used, clippy::panic, clippy::unimplemented)]

pub use ssh_key::private::PrivateKey;
pub use ssh_packet::{Id, Message};

mod error;
pub use error::{Error, Result};

mod stream;

pub mod algorithm;
pub mod session;
