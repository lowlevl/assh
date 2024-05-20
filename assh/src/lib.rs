#![doc = concat!(
    "[![crates.io](https://img.shields.io/crates/v/", env!("CARGO_PKG_NAME"), ")](https://crates.io/crates/", env!("CARGO_PKG_NAME"), ")",
    " ",
    "[![docs.rs](https://img.shields.io/docsrs/", env!("CARGO_PKG_NAME"), ")](https://docs.rs/", env!("CARGO_PKG_NAME"), ")",
    " ",
    "![license](https://img.shields.io/crates/l/", env!("CARGO_PKG_NAME"), ")"
)]
#![doc = ""]
#![doc = env!("CARGO_PKG_DESCRIPTION")]
//!
//! ### Supported algorithms
//!
//! #### Key-exchange:
//! see [`stream::algorithm::Kex`].
//!
//! #### Encryption:
//!
//! see [`stream::algorithm::Cipher`].
//!
//! #### MACs
//!
//! see [`stream::algorithm::Hmac`].
//!
//! #### Compression:
//!
//! see [`stream::algorithm::Compress`].

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::todo,
    clippy::undocumented_unsafe_blocks
)]
#![forbid(unsafe_code)]

mod error;
pub use error::{Error, Result};

mod stream;
pub use stream::algorithm;

pub mod session;
