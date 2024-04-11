use futures::{AsyncBufRead, AsyncWrite};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::{PrivateKey, Signature};
use ssh_packet::{
    arch::MpInt,
    binrw::BinWrite,
    cryptography::EcdhExchange,
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

// TODO: Implement the following legacy key-exchange methods (`diffie-hellman-group14-sha256`, `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1`).

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
    //
    // DiffieHellmanGroup14Sha1,
    //
    // DiffieHellmanGroup1Sha1,
}

impl Kex {
    pub(crate) async fn init<S: AsyncBufRead + AsyncWrite + Unpin>(
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
                let e_c = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
                let q_c = x25519_dalek::PublicKey::from(&e_c);

                stream
                    .send(&KexEcdhInit {
                        q_c: q_c.as_ref().to_vec().into(),
                    })
                    .await?;

                let ecdh: KexEcdhReply = stream.recv().await?.to()?;
                let q_s = x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(&*ecdh.q_s).map_err(|_| Error::KexError)?,
                );

                let secret: MpInt = e_c.diffie_hellman(&q_s).to_bytes().to_vec().into();

                let k_s = ssh_key::PublicKey::from_bytes(&ecdh.k_s)?;
                let exchange = EcdhExchange {
                    v_c: &v_c.to_string().into_bytes().into(),
                    v_s: &v_s.to_string().into_bytes().into(),
                    i_c: &{
                        let mut buffer = Vec::new();
                        i_c.write(&mut std::io::Cursor::new(&mut buffer))?;
                        buffer.into()
                    },
                    i_s: &{
                        let mut buffer = Vec::new();
                        i_s.write(&mut std::io::Cursor::new(&mut buffer))?;
                        buffer.into()
                    },
                    k_s: &ecdh.k_s,
                    q_c: &q_c.as_ref().to_vec().into(),
                    q_s: &q_s.to_bytes().to_vec().into(),
                    k: &secret,
                };
                let hash = exchange.hash::<Sha256>();

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

    pub(crate) async fn reply<S: AsyncBufRead + AsyncWrite + Unpin>(
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
                let ecdh: KexEcdhInit = stream.recv().await?.to()?;

                let e_s = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
                let q_s = x25519_dalek::PublicKey::from(&e_s);

                let q_c = x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(&*ecdh.q_c).map_err(|_| Error::KexError)?,
                );

                let secret: MpInt = e_s.diffie_hellman(&q_c).to_bytes().to_vec().into();

                let k_s = key.public_key().to_bytes()?.into();
                let q_s = q_s.as_ref().to_vec().into();

                let exchange = EcdhExchange {
                    v_c: &v_c.to_string().into_bytes().into(),
                    v_s: &v_s.to_string().into_bytes().into(),
                    i_c: &{
                        let mut buffer = Vec::new();
                        i_c.write(&mut std::io::Cursor::new(&mut buffer))?;
                        buffer.into()
                    },
                    i_s: &{
                        let mut buffer = Vec::new();
                        i_s.write(&mut std::io::Cursor::new(&mut buffer))?;
                        buffer.into()
                    },
                    k_s: &k_s,
                    q_c: &q_c.to_bytes().to_vec().into(),
                    q_s: &q_s,
                    k: &secret,
                };
                let hash = exchange.hash::<Sha256>();

                let signature = Signer::sign(key, &hash);
                stream
                    .send(&KexEcdhReply {
                        k_s,
                        q_s,
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
