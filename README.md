# assh
[![docs.rs](https://img.shields.io/docsrs/assh)](https://docs.rs/assh) [![Crates.io](https://img.shields.io/crates/l/assh)](https://crates.io/crates/assh)

A low-level SSH library handling the transport and key-exchange, not more, not less.

### Project goals

- Code readability.
- Expandability.
- Protocol safety.
  - Forward secrecy.
  - Safe and tested protocol implementation.
  - Support for state-of-the-art protocols and key exchanges.
- 100% crate documentation.
- Exhaustive examples.

### Project non-goals

- Being a standalone ssh server and/or client.
- Exhaustive protocol extensions implementation.
- Being the fastest implementation.
