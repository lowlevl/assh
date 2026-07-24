pub use ssh_key::Algorithm as Key;
use ssh_packet::{arch::NameList, trans::KexInit};

use crate::Error;

use super::Negociate;

impl Negociate for Key {
    const ERR: Error = Error::NoCommonKey;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f> {
        &kex.server_host_key_algorithms
    }
}
