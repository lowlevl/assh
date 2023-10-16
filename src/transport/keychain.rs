use digest::{Digest, FixedOutputReset};
use securefmt::Debug;
use ssh_packet::{arch::MpInt, Mac};

use crate::algorithm::cipher::CipherLike;

#[derive(Debug, Default)]
pub struct KeyChain {
    #[sensitive]
    pub iv: Vec<u8>,
    #[sensitive]
    pub key: Vec<u8>,
    #[sensitive]
    pub hmac: Vec<u8>,
}

impl KeyChain {
    pub fn as_client<D: Digest + FixedOutputReset>(
        secret: &MpInt,
        hash: &[u8],
        session_id: &[u8],
        cipher: &impl CipherLike,
        hmac: &impl Mac,
    ) -> Self {
        let ivsize = cipher.iv_size();
        let keysize = cipher.key_size();
        let hmacsize = hmac.size();

        Self {
            iv: Self::derive::<D>(secret, hash, b'A', session_id, ivsize),
            key: Self::derive::<D>(secret, hash, b'C', session_id, keysize),
            hmac: Self::derive::<D>(secret, hash, b'E', session_id, hmacsize),
        }
    }

    pub fn as_server<D: Digest + FixedOutputReset>(
        secret: &MpInt,
        hash: &[u8],
        session_id: &[u8],
        cipher: &impl CipherLike,
        hmac: &impl Mac,
    ) -> Self {
        let ivsize = cipher.iv_size();
        let keysize = cipher.key_size();
        let hmacsize = hmac.size();

        Self {
            iv: Self::derive::<D>(secret, hash, b'B', session_id, ivsize),
            key: Self::derive::<D>(secret, hash, b'D', session_id, keysize),
            hmac: Self::derive::<D>(secret, hash, b'F', session_id, hmacsize),
        }
    }

    fn derive<D: Digest + FixedOutputReset>(
        secret: &MpInt,
        hash: &[u8],
        kind: u8,
        session_id: &[u8],
        size: usize,
    ) -> Vec<u8> {
        let mut hasher = D::new()
            .chain_update((secret.len() as u32).to_be_bytes())
            .chain_update(secret)
            .chain_update(hash)
            .chain_update([kind])
            .chain_update(session_id);

        let mut key = hasher.finalize_reset().to_vec();

        while key.len() < size {
            hasher = hasher
                .chain_update((secret.len() as u32).to_be_bytes())
                .chain_update(secret)
                .chain_update(hash)
                .chain_update(&key);

            key.extend_from_slice(&hasher.finalize_reset());
        }

        key.resize(size, 0);

        key
    }
}
