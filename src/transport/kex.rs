use futures::{io::BufReader, AsyncRead, AsyncWrite};
use futures_time::{future::FutureExt, time::Duration};
use ssh_packet::{
    trans::{KexEcdhInit, KexEcdhReply},
    Packet,
};
use strum::{EnumString, EnumVariantNames};

use super::TransportPair;
use crate::{Error, Result};

#[derive(Debug, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum KexAlg {
    Curve25519Sha256,

    #[strum(serialize = "curve25519-sha256@libssh.org")]
    Curve25519Sha256Ext,

    DiffieHellmanGroup14Sha256,

    DiffieHellmanGroup14Sha1,

    DiffieHellmanGroup1Sha1,
}

impl KexAlg {
    pub async fn reply<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut BufReader<S>,
        transport: &mut TransportPair,
        timeout: Duration,
    ) -> Result<[u8; 32]> {
        match self {
            KexAlg::Curve25519Sha256 | KexAlg::Curve25519Sha256Ext => {
                let ecdh: KexEcdhInit = Packet::from_async_reader(stream, transport)
                    .timeout(timeout)
                    .await??
                    .decrypt(transport)?;

                tracing::info!("KexDH init: {ecdh:?}");
                let q_c: [u8; 32] = ecdh
                    .q_c
                    .into_vec()
                    .try_into()
                    .map_err(|_| Error::KexError)?;
                let q_c = x25519_dalek::PublicKey::from(q_c);

                let e_s = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
                let q_s = x25519_dalek::PublicKey::from(&e_s);

                let secret = e_s.diffie_hellman(&q_c);

                // let reply = KexEcdhReply { q_s };

                Ok(secret.to_bytes())
            }
            _ => unimplemented!(),
        }
    }

    pub fn init() {}
}
