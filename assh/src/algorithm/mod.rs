//! Supported algorithms for **compression**, **encryption**, **integrity** and **key-exchange**.

// TODO: (feature) Gate insecure algorithms behind an `insecure` feature flag.

mod cipher;
pub use cipher::Cipher;
pub(super) use cipher::CipherState;

mod compress;
pub use compress::Compress;

mod hmac;
pub use hmac::Hmac;

pub(crate) mod kex;
pub use kex::Kex;

pub(crate) mod key;
pub use key::Key;
