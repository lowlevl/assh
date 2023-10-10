use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures_time::time::Duration;
use rand::RngCore;
use ssh_key::PrivateKey;
use ssh_packet::{arch::NameList, trans::KexInit, Id};
use strum::VariantNames;

use crate::{
    algorithm::{kex, key, Cipher, Compress, Hmac, Kex},
    stream::Stream,
    transport::TransportPair,
    Result,
};

/// A session _server_-side configuration.
#[derive(Debug)]
pub struct Server {
    pub id: Id,
    pub timeout: Duration,

    pub keys: Vec<PrivateKey>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            id: Id::v2(
                concat!(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                None::<&str>,
            ),
            keys: vec![],
            timeout: Duration::from_secs(3),
        }
    }
}

#[async_trait]
impl super::Side for Server {
    fn id(&self) -> &Id {
        &self.id
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn kexinit(&self) -> KexInit {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        KexInit {
            cookie,
            kex_algorithms: NameList::new(Kex::VARIANTS),
            server_host_key_algorithms: NameList::new(
                &self
                    .keys
                    .iter()
                    .map(|key| key.algorithm().to_string())
                    .collect::<Vec<_>>(),
            ),
            encryption_algorithms_client_to_server: NameList::new(Cipher::VARIANTS),
            encryption_algorithms_server_to_client: NameList::new(Cipher::VARIANTS),
            mac_algorithms_client_to_server: NameList::new(Hmac::VARIANTS),
            mac_algorithms_server_to_client: NameList::new(Hmac::VARIANTS),
            compression_algorithms_client_to_server: NameList::new(Compress::VARIANTS),
            compression_algorithms_server_to_client: NameList::new(Compress::VARIANTS),
            languages_client_to_server: NameList::default(),
            languages_server_to_client: NameList::default(),
            first_kex_packet_follows: false.into(),
        }
    }

    async fn exchange(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair> {
        let keyalg = key::negociate(&peerkexinit, &kexinit)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.algorithm() == keyalg)
            .expect("Did our KexInit lie to the client ?");

        kex::negociate(&peerkexinit, &kexinit)?
            .reply(stream, peer_id, self.id(), peerkexinit, kexinit, key)
            .await
    }
}
