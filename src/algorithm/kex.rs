use digest::Digest;
use futures::{AsyncRead, AsyncWrite};
use ring::agreement;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::{PrivateKey, Signature};
use ssh_packet::{
    arch::MpInt,
    binrw::BinWrite,
    kex::EcdhExchange,
    trans::{KexEcdhInit, KexEcdhReply, KexInit},
    Id,
};
use strum::{AsRefStr, EnumString};

use crate::{
    stream::{Keys, Stream, Transport, TransportPair},
    Error, Result,
};

use super::{cipher, compress, hmac};

pub fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<Kex> {
    clientkex
        .kex_algorithms
        .preferred_in(&serverkex.kex_algorithms)
        .ok_or(Error::NoCommonKex)?
        .parse()
        .map_err(|_| Error::UnsupportedAlgorithm)
}

/// SSH key-exchange algorithms.
#[non_exhaustive]
#[derive(Debug, PartialEq, EnumString, AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub enum Kex {
    /// Curve25519 ECDH with sha-2-256 digest.
    Curve25519Sha256,

    /// Curve25519 ECDH with sha-2-256 digest (pre-RFC 8731).
    #[strum(serialize = "curve25519-sha256@libssh.org")]
    Curve25519Sha256Libssh,
    //
    // DiffieHellmanGroup14Sha256,

    // DiffieHellmanGroup14Sha1,

    // DiffieHellmanGroup1Sha1,
}

impl Kex {
    pub(crate) async fn init<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut Stream<S>,
        v_c: &Id,
        v_s: &Id,
        i_c: KexInit,
        i_s: KexInit,
    ) -> Result<TransportPair> {
        let (client_hmac, server_hmac) = hmac::negociate(&i_c, &i_s)?;
        let (client_compress, server_compress) = compress::negociate(&i_c, &i_s)?;
        let (client_cipher, server_cipher) = cipher::negociate(&i_c, &i_s)?;

        match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                let e_c = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &ring::rand::SystemRandom::new(),
                )
                .map_err(|_| Error::KexError)?;
                let q_c = e_c.compute_public_key().map_err(|_| Error::KexError)?;

                stream
                    .send(&KexEcdhInit {
                        q_c: q_c.as_ref().to_vec().into(),
                    })
                    .await?;

                let ecdh: KexEcdhReply = stream.recv().await?;
                let q_s = agreement::UnparsedPublicKey::new(&agreement::X25519, &*ecdh.q_s);

                let secret: MpInt = agreement::agree_ephemeral(e_c, &q_s, |key| key.to_vec())
                    .map_err(|_| Error::KexError)?
                    .into();

                let k_s = ssh_key::PublicKey::from_bytes(&ecdh.k_s)?;
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
                    k_s: ecdh.k_s,
                    q_c: q_c.as_ref().to_vec().into(),
                    q_s: q_s.bytes().to_vec().into(),
                    k: secret.clone(),
                };

                let mut buffer = Vec::new();
                exchange.write(&mut std::io::Cursor::new(&mut buffer))?;
                let hash = Sha256::digest(&buffer);

                Verifier::verify(&k_s, &hash, &Signature::try_from(&*ecdh.signature)?)?;

                let session_id = stream.with_session(&hash);

                Ok(TransportPair {
                    rx: Transport {
                        chain: Keys::as_server::<Sha256>(
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
                        chain: Keys::as_client::<Sha256>(
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
                })
            }
        }
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
        let (client_hmac, server_hmac) = hmac::negociate(&i_c, &i_s)?;
        let (client_compress, server_compress) = compress::negociate(&i_c, &i_s)?;
        let (client_cipher, server_cipher) = cipher::negociate(&i_c, &i_s)?;

        match self {
            Self::Curve25519Sha256 | Self::Curve25519Sha256Libssh => {
                let ecdh: KexEcdhInit = stream.recv().await?;

                let e_s = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &ring::rand::SystemRandom::new(),
                )
                .map_err(|_| Error::KexError)?;

                let q_c = agreement::UnparsedPublicKey::new(&agreement::X25519, &*ecdh.q_c);
                let q_s = e_s.compute_public_key().map_err(|_| Error::KexError)?;

                let secret: MpInt = agreement::agree_ephemeral(e_s, &q_c, |key| key.to_vec())
                    .map_err(|_| Error::KexError)?
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

                let session_id = stream.with_session(&hash);

                Ok(TransportPair {
                    rx: Transport {
                        chain: Keys::as_client::<Sha256>(
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
                        chain: Keys::as_server::<Sha256>(
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
                })
            }
        }
    }
}
