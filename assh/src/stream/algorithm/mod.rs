// TODO: (feature) Gate insecure algorithms behind an `insecure` feature flag.

use std::{io::Write, str::FromStr};

use ssh_packet::{arch::NameList, trans::KexInit};

use crate::{Error, Result};

pub mod cipher;
pub mod compress;
pub mod hmac;
pub mod kex;
pub mod key;

pub trait Negociate<S = ()>: Sized + FromStr {
    const ERR: Error;

    fn field<'f>(kex: &'f KexInit) -> &'f NameList<'f>;

    fn negociate(clientkex: &KexInit, serverkex: &KexInit) -> Result<Self> {
        Self::field(clientkex)
            .preferred_in(Self::field(serverkex))
            .ok_or(Self::ERR)?
            .parse()
            .map_err(|_| Self::ERR)
    }
}

/// The SSH key-derivation function,
/// defined in https://datatracker.ietf.org/doc/html/rfc4253#section-7.2.
///
/// This function uses <Cursor as Write>::write_all and ignore it's errors,
/// this is fine because it never fails unless the buffer is full, which is the desired behavior.
fn kdf<const S: usize, H: digest::Digest + digest::FixedOutputReset>(
    kind: u8,
    secret: &[u8],
    hash: &[u8],
    session_id: &[u8],
) -> [u8; S] {
    let mut key = std::io::Cursor::new([0; S]);
    let mut hasher = H::new()
        .chain_update((secret.len() as u32).to_be_bytes())
        .chain_update(secret)
        .chain_update(hash)
        .chain_update([kind])
        .chain_update(session_id);

    key.write_all(&hasher.finalize_reset()).ok();

    while key.position() < S as u64 {
        hasher = hasher
            .chain_update((secret.len() as u32).to_be_bytes())
            .chain_update(secret)
            .chain_update(hash)
            .chain_update(&key.get_ref()[..key.position() as usize]);

        key.write_all(&hasher.finalize_reset()).ok();
    }

    key.into_inner()
}
