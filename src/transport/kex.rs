use futures::{AsyncRead, AsyncWrite};
use ring::agreement;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use ssh_key::PrivateKey;
use ssh_packet::{
    binrw::BinWrite,
    kex::EcdhExchange,
    trans::{KexEcdhInit, KexEcdhReply, KexInit},
    Id,
};
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
        v_c: &Id,
        v_s: &Id,
        i_c: KexInit,
        i_s: KexInit,
        key: &PrivateKey,
    ) -> Result<Vec<u8>> {
        match self {
            KexAlg::Curve25519Sha256 | KexAlg::Curve25519Sha256Ext => {
                let ecdh: KexEcdhInit = stream.recv().await?;

                let e_s = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &ring::rand::SystemRandom::new(),
                )?;

                let q_c = agreement::UnparsedPublicKey::new(&agreement::X25519, &*ecdh.q_c);
                let q_s = e_s.compute_public_key()?;

                let secret =
                    agreement::agree_ephemeral(e_s, &q_c, Error::KexError, |key| Ok(key.to_vec()))?;

                let exchange = EcdhExchange {
                    v_c: v_c.to_string().as_bytes().to_vec().into(),
                    v_s: v_s.to_string().as_bytes().to_vec().into(),
                    i_c,
                    i_s,
                    k_s: key.public_key().to_bytes()?.into(),
                    q_c: q_c.bytes().to_vec().into(),
                    q_s: q_s.as_ref().to_vec().into(),
                    k: secret.clone().into(),
                };

                let mut buffer = Vec::new();
                exchange.write(&mut std::io::Cursor::new(&mut buffer))?;

                let signature = <dyn Signer<_>>::sign(key, &Sha256::digest(&buffer));

                stream
                    .send(&KexEcdhReply {
                        k_s: exchange.k_s,
                        q_s: exchange.q_s,
                        signature: signature.to_vec().into(),
                    })
                    .await?;

                Ok(secret)
            }
            _ => unimplemented!(),
        }
    }

    pub fn init() {}
}
