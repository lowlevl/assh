# assh
[![docs.rs](https://img.shields.io/docsrs/assh)](https://docs.rs/assh) [![Crates.io](https://img.shields.io/crates/l/assh)](https://crates.io/crates/assh)

A low-level SSH library handling the transport and key-exchange, not more, not less.

### Possible improvements
- Client-side cryptographic verification of Diffie-Hellmann exchange (!!).
- 100% crate documentation.
- Implement compression & decompression algorithms (now broken).
- Implement legacy key exchange methods (`diffie-hellman-group14-sha256`, `diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1`).
- Implement latest ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`).
- Getting rid of dynamic dispatch altogether.
- Get rid of `ring` for Diffie-Hellman ?
- 100% test coverage ?
