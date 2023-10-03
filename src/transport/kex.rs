use digest::Digest;
use futures::{AsyncRead, AsyncWrite};
use ring::agreement;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use ssh_key::PrivateKey;
use ssh_packet::{
    binrw::BinWrite,
    kex::EcdhExchange,
    trans::{KexEcdhInit, KexEcdhReply, KexInit},
    Id,
};
use strum::{EnumString, EnumVariantNames};

use super::{KeyChain, Transport, TransportPair};
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
        ctos_alg: Transport,
        stoc_alg: Transport,
    ) -> Result<TransportPair> {
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
                    v_c: v_c.to_string().into_bytes().into(),
                    v_s: v_s.to_string().into_bytes().into(),
                    i_c: {
                        let mut buffer = Vec::new();
                        i_c.write(&mut std::io::Cursor::new(&mut buffer))?;
                        buffer.into()
                    },
                    i_s: {
                        let mut buffer = Vec::new();
                        i_s.write(&mut std::io::Cursor::new(&mut buffer))?;
                        buffer.into()
                    },
                    k_s: key.public_key().to_bytes()?.into(),
                    q_c: q_c.bytes().to_vec().into(),
                    q_s: q_s.as_ref().to_vec().into(),
                    k: secret.clone().into(),
                };

                let mut buffer = Vec::new();
                exchange.write(&mut std::io::Cursor::new(&mut buffer))?;
                let hash = Sha256::digest(&buffer);

                let signature = <dyn Signer<_>>::sign(key, &hash);

                stream
                    .send(&KexEcdhReply {
                        k_s: exchange.k_s,
                        q_s: exchange.q_s,
                        signature: signature.to_vec().into(),
                    })
                    .await?;

                let session_id = stream.with_session(&hash);

                let pair = TransportPair {
                    rchain: KeyChain::as_client::<Sha256>(
                        &secret,
                        &hash,
                        session_id,
                        &ctos_alg.encrypt,
                        &ctos_alg.hmac,
                    ),
                    ralg: ctos_alg,
                    tchain: KeyChain::as_server::<Sha256>(
                        &secret,
                        &hash,
                        session_id,
                        &stoc_alg.encrypt,
                        &stoc_alg.hmac,
                    ),
                    talg: stoc_alg,
                };

                Ok(pair)
            }
            _ => unimplemented!(),
        }
    }
}
