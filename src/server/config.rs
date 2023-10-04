use futures_time::time::Duration;
use rand::RngCore;
use ssh_key::PrivateKey;
use ssh_packet::{arch::NameList, trans::KexInit, Id};
use strum::VariantNames;

use crate::{
    transport::{CompressAlg, EncryptAlg, HmacAlg, KexAlg},
    Result,
};

#[derive(Debug)]
pub struct Config {
    pub id: Id,
    pub keys: Vec<PrivateKey>,
    pub timeout: Duration,
}

impl Default for Config {
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

impl Config {
    pub fn kexinit(&self) -> Result<KexInit> {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        Ok(KexInit {
            cookie,
            kex_algorithms: NameList::new(KexAlg::VARIANTS),
            server_host_key_algorithms: NameList::new(
                &self
                    .keys
                    .iter()
                    .map(|key| key.algorithm().to_string())
                    .collect::<Vec<_>>(),
            ),
            encryption_algorithms_client_to_server: NameList::new(EncryptAlg::VARIANTS),
            encryption_algorithms_server_to_client: NameList::new(EncryptAlg::VARIANTS),
            mac_algorithms_client_to_server: NameList::new(HmacAlg::VARIANTS),
            mac_algorithms_server_to_client: NameList::new(HmacAlg::VARIANTS),
            compression_algorithms_client_to_server: NameList::new(CompressAlg::VARIANTS),
            compression_algorithms_server_to_client: NameList::new(CompressAlg::VARIANTS),
            languages_client_to_server: NameList::default(),
            languages_server_to_client: NameList::default(),
            first_kex_packet_follows: false.into(),
        })
    }
}
