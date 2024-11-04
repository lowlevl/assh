use digest::{Digest, FixedOutputReset};
use secrecy::{ExposeSecret, SecretBox};
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::{PrivateKey, Signature};
use ssh_packet::{
    arch::MpInt,
    crypto::exchange,
    trans::{KexEcdhInit, KexEcdhReply, KexInit},
    Id,
};

use crate::{
    algorithm::{Cipher, Hmac},
    stream::Stream,
    Error, Pipe, Result,
};

use super::Keys;

#[allow(clippy::too_many_arguments)] // The key exchange requires all of these informations
pub async fn as_client<H: Digest + FixedOutputReset>(
    stream: &mut Stream<impl Pipe>,
    v_c: &Id,
    v_s: &Id,
    i_c: KexInit<'_>,
    i_s: KexInit<'_>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
    client_hmac: &Hmac,
    server_hmac: &Hmac,
) -> Result<(Keys, Keys)> {
    let e_c = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
    let q_c = x25519_dalek::PublicKey::from(&e_c);

    stream
        .send(&KexEcdhInit {
            q_c: q_c.as_ref().into(),
        })
        .await?;

    let ecdh: KexEcdhReply = stream.recv().await?.to()?;
    let q_s = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(ecdh.q_s.as_ref()).map_err(|_| Error::KexError)?,
    );

    let secret = e_c.diffie_hellman(&q_s);
    let secret = SecretBox::new(MpInt::positive(secret.as_bytes()).into());

    let k_s = ssh_key::PublicKey::from_bytes(&ecdh.k_s)?;
    let hash = exchange::Ecdh {
        v_c: v_c.to_string().into_bytes().into(),
        v_s: v_s.to_string().into_bytes().into(),
        i_c: (&i_c).into(),
        i_s: (&i_s).into(),
        k_s: ecdh.k_s,
        q_c: q_c.as_ref().into(),
        q_s: q_s.as_ref().into(),
        k: secret.expose_secret().as_borrow(),
    }
    .hash::<H>();

    Verifier::verify(&k_s, &hash, &Signature::try_from(ecdh.signature.as_ref())?)?;

    let session_id = stream.with_session(&hash);

    Ok((
        Keys::as_client::<H>(
            secret.expose_secret(),
            &hash,
            session_id,
            client_cipher,
            client_hmac,
        ),
        Keys::as_server::<H>(
            secret.expose_secret(),
            &hash,
            session_id,
            server_cipher,
            server_hmac,
        ),
    ))
}

#[allow(clippy::too_many_arguments)] // The key exchange requires all of these informations
pub async fn as_server<H: Digest + FixedOutputReset>(
    stream: &mut Stream<impl Pipe>,
    v_c: &Id,
    v_s: &Id,
    i_c: KexInit<'_>,
    i_s: KexInit<'_>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
    client_hmac: &Hmac,
    server_hmac: &Hmac,
    key: &PrivateKey,
) -> Result<(Keys, Keys)> {
    let ecdh: KexEcdhInit = stream.recv().await?.to()?;

    let e_s = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
    let q_s = x25519_dalek::PublicKey::from(&e_s);

    let q_c = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(ecdh.q_c.as_ref()).map_err(|_| Error::KexError)?,
    );

    let secret = e_s.diffie_hellman(&q_c);
    let secret = SecretBox::new(MpInt::positive(secret.as_bytes()).into());

    let k_s = key.public_key().to_bytes()?;

    let hash = exchange::Ecdh {
        v_c: v_c.to_string().into_bytes().into(),
        v_s: v_s.to_string().into_bytes().into(),
        i_c: (&i_c).into(),
        i_s: (&i_s).into(),
        k_s: k_s.as_slice().into(),
        q_c: q_c.as_ref().into(),
        q_s: q_s.as_ref().into(),
        k: secret.expose_secret().as_borrow(),
    }
    .hash::<H>();

    let signature = Signer::sign(key, &hash);

    stream
        .send(&KexEcdhReply {
            k_s: k_s.into(),
            q_s: q_s.as_ref().into(),
            signature: signature.to_vec().into(),
        })
        .await?;

    let session_id = stream.with_session(&hash);

    Ok((
        Keys::as_client::<H>(
            secret.expose_secret(),
            &hash,
            session_id,
            client_cipher,
            client_hmac,
        ),
        Keys::as_server::<H>(
            secret.expose_secret(),
            &hash,
            session_id,
            server_cipher,
            server_hmac,
        ),
    ))
}
