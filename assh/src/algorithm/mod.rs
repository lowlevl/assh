//! Supported algorithms for **compression**, **encryption**, **integrity** and **key-exchange**.

// TODO: (feature) Gate insecure algorithms behind an `insecure` feature flag.

use std::str::FromStr;

use ssh_packet::{arch::NameList, trans::KexInit};

use crate::{Error, Result};

pub(crate) trait Negociate<S = ()>: Sized + FromStr {
    const ERR: Error;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f>;

    fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<Self> {
        Self::field(clientkex)
            .preferred_in(Self::field(serverkex))
            .ok_or(Self::ERR)?
            .parse()
            .map_err(|_| Self::ERR)
    }
}

mod cipher;
pub use cipher::Cipher;
pub(super) use cipher::CipherState;

mod compress;
pub use compress::Compress;

mod hmac;
pub use hmac::Hmac;

mod kex;
pub use kex::Kex;
pub(super) use kex::KexMeta;

mod key;
pub use key::Key;
