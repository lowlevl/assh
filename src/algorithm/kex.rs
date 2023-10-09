use std::str::FromStr;

use digest::Digest;
use futures::{AsyncRead, AsyncWrite};
use ring::agreement;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use ssh_key::PrivateKey;
use ssh_packet::{
    arch::MpInt,
    binrw::BinWrite,
    kex::EcdhExchange,
    trans::{KexEcdhInit, KexEcdhReply, KexInit},
    Id,
};
use strum::{EnumString, EnumVariantNames};

use crate::{
    stream::Stream,
    transport::{KeyChain, Transport, TransportPair},
    Error, Result,
};

use super::{Cipher, Compress, Hmac};

#[derive(Debug, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum Kex {
    Curve25519Sha256,

    #[strum(serialize = "curve25519-sha256@libssh.org")]
    Curve25519Sha256Libssh,

    DiffieHellmanGroup14Sha256,

    DiffieHellmanGroup14Sha1,

    DiffieHellmanGroup1Sha1,
}

impl Kex {
    pub(crate) fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<Self> {
        clientkex
            .kex_algorithms
            .preferred_in(&serverkex.kex_algorithms)
            .ok_or(Error::NoCommonKex)?
            .parse()
            .map_err(|_| Error::UnsupportedAlgorithm)
    }

    pub(crate) async fn reply<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut Stream<S>,
        v_c: &Id,
        v_s: &Id,
        i_c: KexInit,
        i_s: KexInit,
        key: &PrivateKey,
    ) -> Result<TransportPair> {
        let (hash, secret) = match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                let ecdh: KexEcdhInit = stream.recv().await?;

                let e_s = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &ring::rand::SystemRandom::new(),
                )?;

                let q_c = agreement::UnparsedPublicKey::new(&agreement::X25519, &*ecdh.q_c);
                let q_s = e_s.compute_public_key()?;

                let secret: MpInt =
                    agreement::agree_ephemeral(e_s, &q_c, Error::KexError, |key| Ok(key.to_vec()))?
                        .into();

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
                    k: secret.clone(),
                };

                let mut buffer = Vec::new();
                exchange.write(&mut std::io::Cursor::new(&mut buffer))?;
                let hash = Sha256::digest(&buffer);

                let signature = Signer::sign(key, &hash);
                stream
                    .send(&KexEcdhReply {
                        k_s: exchange.k_s,
                        q_s: exchange.q_s,
                        signature: signature.to_vec().into(),
                    })
                    .await?;

                (hash, secret)
            }
            _ => unimplemented!(),
        };

        let session_id = stream.with_session(&hash);

        let (client_hmac, server_hmac) = Hmac::negociate(&i_c, &i_s)?;
        let (client_compress, server_compress) = Compress::negociate(&i_c, &i_s)?;
        let (client_cipher, server_cipher) = (
            Cipher::from_str(
                i_c.encryption_algorithms_client_to_server
                    .preferred_in(&i_s.encryption_algorithms_client_to_server)
                    .ok_or(Error::NoCommonCipher)?,
            )
            .map_err(|_| Error::UnsupportedAlgorithm)?,
            Cipher::from_str(
                i_c.encryption_algorithms_server_to_client
                    .preferred_in(&i_s.encryption_algorithms_server_to_client)
                    .ok_or(Error::NoCommonCipher)?,
            )
            .map_err(|_| Error::UnsupportedAlgorithm)?,
        );

        let pair = TransportPair {
            rx: Transport {
                chain: KeyChain::as_client::<Sha256>(
                    &secret,
                    &hash,
                    session_id,
                    &client_cipher,
                    &client_hmac,
                ),
                state: None,
                cipher: client_cipher,
                hmac: client_hmac,
                compress: client_compress,
            },
            tx: Transport {
                chain: KeyChain::as_server::<Sha256>(
                    &secret,
                    &hash,
                    session_id,
                    &server_cipher,
                    &server_hmac,
                ),
                state: None,
                cipher: server_cipher,
                hmac: server_hmac,
                compress: server_compress,
            },
        };

        Ok(pair)
    }
}
