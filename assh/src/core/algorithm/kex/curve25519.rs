use std::{io, task};

use futures::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretBox};
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::Signature;
use ssh_packet::{
    IntoPacket, Packet,
    arch::MpInt,
    crypto::exchange,
    trans::{KexEcdhInit, KexEcdhReply},
};

use crate::{
    Error, Pipe, Result,
    core::{Core, rx, tx},
};

type Hash = sha2::Sha256;

#[derive(Default)]
pub enum Client {
    #[default]
    Init,
    AwaitReply {
        e_c: Option<x25519_dalek::EphemeralSecret>,
        q_c: x25519_dalek::PublicKey,
    },
}

impl super::Clientside<Client> {
    pub fn poll(
        &mut self,
        cx: &mut task::Context,
        core: &mut Core<impl Pipe>,
    ) -> task::Poll<Result<(rx::Transport, tx::Transport)>> {
        loop {
            match &mut self.kex {
                Client::Init => {
                    futures::ready!(core.poll_ready_unpin(cx))?;

                    let e_c = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rng());
                    let q_c = x25519_dalek::PublicKey::from(&e_c);

                    core.start_send_unpin(
                        &KexEcdhInit {
                            q_c: q_c.as_ref().into(),
                        }
                        .into_packet(),
                    )?;

                    self.kex = Client::AwaitReply {
                        e_c: Some(e_c),
                        q_c,
                    };
                }

                Client::AwaitReply { e_c, q_c } => {
                    futures::ready!(core.poll_flush_unpin(cx))?;

                    let data = futures::ready!(core.poll_next_unpin(cx))
                        .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))??;
                    let ecdh = Packet(data.to_vec()).to::<KexEcdhReply>()?;

                    let q_s = x25519_dalek::PublicKey::from(
                        <[u8; 32]>::try_from(ecdh.q_s.as_ref()).map_err(|_| Error::KexError)?,
                    );

                    let secret = e_c
                        .take()
                        .expect("the `e_c` was already consumed")
                        .diffie_hellman(&q_s);
                    let secret = SecretBox::new(MpInt::positive(secret.as_bytes()).into());

                    let k_s = ssh_key::PublicKey::from_bytes(&ecdh.k_s)?;
                    let hash = exchange::Ecdh {
                        v_c: self.client.id.to_string().into_bytes().into(),
                        v_s: self.server.id.to_string().into_bytes().into(),
                        i_c: (&self.client.kexinit).into(),
                        i_s: (&self.server.kexinit).into(),
                        k_s: ecdh.k_s,
                        q_c: q_c.as_ref().into(),
                        q_s: q_s.as_ref().into(),
                        k: secret.expose_secret().as_borrow(),
                    }
                    .hash::<Hash>();

                    Verifier::verify(&k_s, &hash, &Signature::try_from(ecdh.signature.as_ref())?)?;

                    // TODO: (security) verify public-key against a known-hosts database

                    let session_id = core.with_session(&hash);

                    let rx = rx::Transport::as_client::<Hash>(
                        &self.server,
                        secret.expose_secret().as_ref(),
                        &hash,
                        session_id,
                    );
                    let tx = tx::Transport::as_client::<Hash>(
                        &self.client,
                        secret.expose_secret().as_ref(),
                        &hash,
                        session_id,
                    );

                    break task::Poll::Ready(Ok((rx, tx)));
                }
            }
        }
    }
}

#[derive(Default)]
pub enum Server {
    #[default]
    AwaitInit,
    Reply {
        q_c: x25519_dalek::PublicKey,
    },
}

impl super::Serverside<Server> {
    pub fn poll(
        &mut self,
        cx: &mut task::Context,
        core: &mut Core<impl Pipe>,
    ) -> task::Poll<Result<(rx::Transport, tx::Transport)>> {
        loop {
            match &mut self.kex {
                Server::AwaitInit => {
                    let data = futures::ready!(core.poll_next_unpin(cx))
                        .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))??;
                    let ecdh = Packet(data.to_vec()).to::<KexEcdhInit>()?;

                    let q_c = x25519_dalek::PublicKey::from(
                        <[u8; 32]>::try_from(ecdh.q_c.as_ref()).map_err(|_| Error::KexError)?,
                    );

                    self.kex = Server::Reply { q_c };
                }

                Server::Reply { q_c } => {
                    futures::ready!(core.poll_ready_unpin(cx))?;

                    let e_s = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rng());
                    let q_s = x25519_dalek::PublicKey::from(&e_s);

                    let secret = e_s.diffie_hellman(q_c);
                    let secret = SecretBox::new(MpInt::positive(secret.as_bytes()).into());

                    let k_s = self.key.public_key().to_bytes()?;

                    let hash = exchange::Ecdh {
                        v_c: self.client.id.to_string().into_bytes().into(),
                        v_s: self.server.id.to_string().into_bytes().into(),
                        i_c: (&self.client.kexinit).into(),
                        i_s: (&self.server.kexinit).into(),
                        k_s: k_s.as_slice().into(),
                        q_c: q_c.as_ref().into(),
                        q_s: q_s.as_ref().into(),
                        k: secret.expose_secret().as_borrow(),
                    }
                    .hash::<Hash>();

                    let signature = Signer::sign(&self.key, &hash);

                    core.start_send_unpin(
                        &KexEcdhReply {
                            k_s: k_s.into(),
                            q_s: q_s.as_ref().into(),
                            signature: signature.to_bytes().into(),
                        }
                        .into_packet(),
                    )?;

                    let session_id = core.with_session(&hash);

                    let rx = rx::Transport::as_server::<Hash>(
                        &self.client,
                        secret.expose_secret().as_ref(),
                        &hash,
                        session_id,
                    );
                    let tx = tx::Transport::as_server::<Hash>(
                        &self.server,
                        secret.expose_secret().as_ref(),
                        &hash,
                        session_id,
                    );

                    break task::Poll::Ready(Ok((rx, tx)));
                }
            }
        }
    }
}
