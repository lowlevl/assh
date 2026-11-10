use ssh_packet::{arch::id::Id, trans::KexInit};

use crate::{
    Result,
    core::algorithm::{Negociate, cipher::Cipher, compress::Compress, hmac::Hmac},
    side::{client::Client, server::Server},
};

pub struct Meta {
    pub id: Id,
    pub kexinit: KexInit<'static>,
    pub compress: Compress,
    pub cipher: Cipher,
    pub hmac: Hmac,
}

impl Meta {
    pub fn new(
        client: (Id, KexInit<'static>),
        server: (Id, KexInit<'static>),
    ) -> Result<(Self, Self)> {
        let ccompress = <Compress as Negociate<Client>>::negociate(&client.1, &server.1)?;
        let ccipher = <Cipher as Negociate<Client>>::negociate(&client.1, &server.1)?;
        let chmac = <Hmac as Negociate<Client>>::negociate(&client.1, &server.1)?;

        let scompress = <Compress as Negociate<Server>>::negociate(&client.1, &server.1)?;
        let scipher = <Cipher as Negociate<Server>>::negociate(&client.1, &server.1)?;
        let shmac = <Hmac as Negociate<Server>>::negociate(&client.1, &server.1)?;

        let client = Self {
            id: client.0,
            kexinit: client.1,
            compress: ccompress,
            cipher: ccipher,
            hmac: chmac,
        };

        let server = Self {
            id: server.0,
            kexinit: server.1,
            compress: scompress,
            cipher: scipher,
            hmac: shmac,
        };

        Ok((client, server))
    }
}
