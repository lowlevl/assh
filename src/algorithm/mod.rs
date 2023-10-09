//! Algorithm implementations for **compression**, **encryption**, **integrity** and **key-exchange**.

pub use ssh_key::Algorithm as Key;

mod compress;
pub use compress::Compress;

mod cipher;
pub use cipher::Cipher;
pub(crate) use cipher::{CipherLike, CipherState};

mod hmac;
pub use hmac::Hmac;

mod kex;
pub use kex::Kex;
