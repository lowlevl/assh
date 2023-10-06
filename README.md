# assh
[![docs.rs](https://img.shields.io/docsrs/assh)](https://docs.rs/assh) [![Crates.io](https://img.shields.io/crates/l/assh)](https://crates.io/crates/assh)

A low-level SSH library handling the transport and key-exchange, not more, not less.

## Supported algorithms
✅: **Supported** ⏳: **Planned** ❌: **Not planned**

#### Key-exchange:
- ✅ `curve25519-sha256` / `curve25519-sha256@libssh.org`
- ⏳ `diffie-hellman-group14-sha256`
- ⏳ `diffie-hellman-group14-sha1`
- ⏳ `diffie-hellman-group1-sha1`

#### Encryption:

- ⏳ `chacha20-poly1305@openssh.com`
- ⏳ `aes256-gcm@openssh.com`
- ⏳ `aes128-gcm@openssh.com`
- ✅ `aes256-ctr`
- ✅ `aes192-ctr`
- ✅ `aes128-ctr`
- ✅ `aes256-cbc`
- ✅ `aes192-cbc`
- ✅ `aes128-cbc`
- ✅ `3des-cbc`
- ✅ `none`

#### MACs

- ✅ `hmac-sha2-512-etm@openssh.com`
- ✅ `hmac-sha2-256-etm@openssh.com`
- ✅ `hmac-sha2-512`
- ✅ `hmac-sha2-256`
- ✅ `hmac-sha1-etm@openssh.com`
- ✅ `hmac-sha1`
- ✅ `none`

#### Compression:

- ⏳ `zlib@openssh.com`
- ⏳ `zlib`
- ✅ `none`
