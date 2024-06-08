pub use ssh_key::Algorithm as Key;
use ssh_packet::trans::KexInit;

use crate::{Error, Result};

pub fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<Key> {
    clientkex
        .server_host_key_algorithms
        .preferred_in(&serverkex.server_host_key_algorithms)
        .ok_or(Error::NoCommonKey)?
        .parse()
        .map_err(|_| Error::NoCommonKex)
}
