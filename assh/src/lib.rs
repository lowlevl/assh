#![doc = concat!(
    "[![docs.rs](https://img.shields.io/docsrs/", env!("CARGO_PKG_NAME"), ")](https://docs.rs/", env!("CARGO_PKG_NAME"), ")",
    " ",
    "[![crates.io](https://img.shields.io/crates/l/", env!("CARGO_PKG_NAME"), ")](https://crates.io/crates/", env!("CARGO_PKG_NAME"), ")"
)]
#![doc = ""]
#![doc = env!("CARGO_PKG_DESCRIPTION")]
//!
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
#![warn(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::todo,
    clippy::undocumented_unsafe_blocks
)]

#[doc(no_inline)]
pub use ssh_key::private::PrivateKey;
#[doc(no_inline)]
pub use ssh_packet::{Id, Message};

mod error;
pub use error::{Error, Result};

pub mod algorithm;
pub mod session;

mod stream;
