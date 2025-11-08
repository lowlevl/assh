use digest::{Digest, FixedOutputReset};
use secrecy::{ExposeSecret, SecretBox};
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::{PrivateKey, Signature};
use ssh_packet::{
    arch::MpInt,
    crypto::exchange,
    trans::{KexEcdhInit, KexEcdhReply},
};

use crate::{Error, Pipe, Result, stream::Stream};

use super::{KexMeta, Keys, Transport};

pub async fn as_client<H: Digest + FixedOutputReset>(
    stream: &mut Stream<impl Pipe>,
    client: KexMeta<'_>,
    server: KexMeta<'_>,
) -> Result<(Transport, Transport)> {
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
        v_c: client.id.to_string().into_bytes().into(),
        v_s: server.id.to_string().into_bytes().into(),
        i_c: (client.kexinit).into(),
        i_s: (server.kexinit).into(),
        k_s: ecdh.k_s,
        q_c: q_c.as_ref().into(),
        q_s: q_s.as_ref().into(),
        k: secret.expose_secret().as_borrow(),
    }
    .hash::<H>();

    Verifier::verify(&k_s, &hash, &Signature::try_from(ecdh.signature.as_ref())?)?;

    let session_id = stream.with_session(&hash);

    let keys = Keys::as_client::<H>(
        secret.expose_secret(),
        &hash,
        session_id,
        &client.cipher,
        &client.hmac,
    );
    let client = client.into_transport(keys);

    let keys = Keys::as_server::<H>(
        secret.expose_secret(),
        &hash,
        session_id,
        &server.cipher,
        &server.hmac,
    );
    let server = server.into_transport(keys);

    Ok((client, server))
}

pub async fn as_server<H: Digest + FixedOutputReset>(
    stream: &mut Stream<impl Pipe>,
    client: KexMeta<'_>,
    server: KexMeta<'_>,
    key: &PrivateKey,
) -> Result<(Transport, Transport)> {
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
        v_c: client.id.to_string().into_bytes().into(),
        v_s: server.id.to_string().into_bytes().into(),
        i_c: (client.kexinit).into(),
        i_s: (server.kexinit).into(),
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

    let keys = Keys::as_client::<H>(
        secret.expose_secret(),
        &hash,
        session_id,
        &client.cipher,
        &client.hmac,
    );
    let client = client.into_transport(keys);

    let keys = Keys::as_server::<H>(
        secret.expose_secret(),
        &hash,
        session_id,
        &server.cipher,
        &server.hmac,
    );
    let server = server.into_transport(keys);

    Ok((client, server))
}
