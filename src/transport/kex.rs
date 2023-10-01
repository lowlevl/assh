use std::vec;

use futures::{AsyncRead, AsyncWrite};
use ring::agreement;
use ssh_key::PrivateKey;
use ssh_packet::trans::{KexEcdhInit, KexEcdhReply};
use strum::{EnumString, EnumVariantNames};

use crate::{stream::Stream, Error, Result};

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
        stream: &mut Stream<S>,
        key: &PrivateKey,
    ) -> Result<Vec<u8>> {
        match self {
            KexAlg::Curve25519Sha256 | KexAlg::Curve25519Sha256Ext => {
                let ecdh: KexEcdhInit = stream.recv().await?;

                let e_s = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &ring::rand::SystemRandom::new(),
                )?;

                let q_c = agreement::UnparsedPublicKey::new(&agreement::X25519, ecdh.q_c);
                let q_s = e_s.compute_public_key()?;

                let secret =
                    agreement::agree_ephemeral(e_s, &q_c, Error::KexError, |key| Ok(key.to_vec()))?;

                let reply = KexEcdhReply {
                    k_s: key.public_key().to_bytes()?.into(),
                    q_s: q_s.as_ref().to_vec().into(),
                    signature: vec![].into(),
                };
                stream.send(&reply).await?;

                Ok(secret)
            }
            _ => unimplemented!(),
        }
    }

    pub fn init() {}
}
