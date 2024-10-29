use digest::{Digest, FixedOutputReset};
use secrecy::SecretBox;
use ssh_packet::Mac;

use super::algorithm::Cipher;

#[derive(Debug, Default)]
pub struct Keys {
    /// Cipher _initialization vector_.
    pub iv: SecretBox<Vec<u8>>,

    /// Cipher _key_.
    pub key: SecretBox<Vec<u8>>,

    /// Hmac _key_.
    pub hmac: SecretBox<Vec<u8>>,
}

impl Keys {
    pub fn as_client<D: Digest + FixedOutputReset>(
        secret: &impl AsRef<[u8]>,
        hash: &[u8],
        session_id: &[u8],
        cipher: &Cipher,
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
        secret: &impl AsRef<[u8]>,
        hash: &[u8],
        session_id: &[u8],
        cipher: &Cipher,
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
        secret: &impl AsRef<[u8]>,
        hash: &[u8],
        kind: u8,
        session_id: &[u8],
        size: usize,
    ) -> SecretBox<Vec<u8>> {
        SecretBox::<Vec<u8>>::init_with_mut(|key| {
            let mut hasher = D::new()
                .chain_update((secret.as_ref().len() as u32).to_be_bytes())
                .chain_update(secret)
                .chain_update(hash)
                .chain_update([kind])
                .chain_update(session_id);

            key.extend_from_slice(&hasher.finalize_reset());

            while key.len() < size {
                hasher = hasher
                    .chain_update((secret.as_ref().len() as u32).to_be_bytes())
                    .chain_update(secret)
                    .chain_update(hash)
                    .chain_update(&*key);

                key.extend_from_slice(&hasher.finalize_reset());
            }

            key.truncate(size);
        })
    }
}
