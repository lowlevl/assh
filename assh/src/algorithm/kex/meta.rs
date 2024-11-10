use std::any::TypeId;

use ssh_packet::{trans::KexInit, Id};

use crate::{
    algorithm::{Cipher, Compress, Hmac, Negociate},
    side::{client::Client, server::Server, Side},
    stream::{Keys, Transport},
    Result,
};

pub struct KexMeta<'k> {
    pub id: &'k Id,

    pub compress: Compress,
    pub cipher: Cipher,
    pub hmac: Hmac,

    pub kexinit: &'k KexInit<'k>,
}

impl<'k> KexMeta<'k> {
    pub fn new<S: Side>(
        id: &'k Id,
        clientkex: &'k KexInit<'k>,
        serverkex: &'k KexInit<'k>,
    ) -> Result<Self>
    where
        Compress: Negociate<S>,
        Cipher: Negociate<S>,
        Hmac: Negociate<S>,
    {
        Ok(Self {
            id,
            compress: <Compress as Negociate<S>>::negociate(clientkex, serverkex)?,
            cipher: <Cipher as Negociate<S>>::negociate(clientkex, serverkex)?,
            hmac: <Hmac as Negociate<S>>::negociate(clientkex, serverkex)?,
            kexinit: if TypeId::of::<S>() == TypeId::of::<Client>() {
                clientkex
            } else if TypeId::of::<S>() == TypeId::of::<Server>() {
                serverkex
            } else {
                unreachable!("There should not be any other struct implementing `Side`")
            },
        })
    }

    pub fn into_transport(self, keys: Keys) -> Transport {
        let Self {
            compress,
            cipher,
            hmac,
            ..
        } = self;

        Transport {
            compress,
            cipher,
            hmac,
            state: None,
            chain: keys,
        }
    }
}
