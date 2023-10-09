use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use rand::RngCore;
use ssh_packet::{arch::NameList, trans::KexInit, Id};
use strum::VariantNames;

use crate::{
    algorithm::{Cipher, Compress, Hmac, Kex},
    stream::Stream,
    transport::TransportPair,
    Error, Result,
};

mod config;
pub use config::Config;

pub enum Server {}

#[async_trait]
impl super::Side for Server {
    type Config = Config;

    async fn exchange(
        config: &Self::Config,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
        kexinit: KexInit,
        peerkexinit: KexInit,
        peer_id: &Id,
    ) -> Result<TransportPair> {
        let kexalg = Kex::negociate(&peerkexinit, &kexinit)?;
        let keyalg = peerkexinit
            .server_host_key_algorithms
            .preferred_in(&kexinit.server_host_key_algorithms)
            .ok_or(Error::NoCommonKey)?
            .parse()
            .map_err(|_| Error::UnsupportedAlgorithm)?;

        let key = config
            .keys
            .iter()
            .find(|key| key.algorithm() == keyalg)
            .expect("Did our KexInit lie to the client ?");

        kexalg
            .reply(stream, peer_id, &config.id, peerkexinit, kexinit, key)
            .await
    }

    fn kexinit(config: &Self::Config) -> KexInit {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        KexInit {
            cookie,
            kex_algorithms: NameList::new(Kex::VARIANTS),
            server_host_key_algorithms: NameList::new(
                &config
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
}
