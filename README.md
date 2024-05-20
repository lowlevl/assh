# assh
![license](https://img.shields.io/crates/l/assh) ![documentation 100%](https://img.shields.io/badge/documentation-100%25-8A2BE2) ![forbid unsafe](https://img.shields.io/badge/forbid-unsafe-red)

A low-level SSH library handling the transport and key-exchange, not more, not less, with extensions for [`SSH-USERAUTH`] and [`SSH-CONNECT`].

<p align="center">

|`assh`|`assh-auth`|`assh-connect`|
|:----:|:---------:|:------------:|
|[![crates.io](https://img.shields.io/crates/v/assh.svg)](https://crates.io/crates/assh)|[![crates.io](https://img.shields.io/crates/v/assh-auth.svg)](https://crates.io/crates/assh-auth)|[![crates.io](https://img.shields.io/crates/v/assh-connect.svg)](https://crates.io/crates/assh-connect)|
|[![docs.rs](https://img.shields.io/docsrs/assh)](https://docs.rs/assh)|[![docs.rs](https://img.shields.io/docsrs/assh-auth)](https://docs.rs/assh-auth)|[![docs.rs](https://img.shields.io/docsrs/assh-connect)](https://docs.rs/assh-connect)

</p>

## Overview

The project comes in different crates that each treat some specific layer of the protocol, for readability and separation of concerns.

These crates use the _[ssh-packet](https://docs.rs/ssh-packet)_ crate as it's binary serialization & deserialization layer, which is also maintained by the maintainer(s) of this project.

### Goals

- Provide a documented, readable and maintainable code for the SSH protocol in Rust.
- Protocol safety, including a safe & tested protocol implementation, some sort of forward secrecy and implementation of the safest ciphers and key-exchanges available.

### Non-goals

- Be the fastest implementation, _this project is more angled towards having a secure and maintainable code_.
- Extensive protocol extension implementations, _this is why the project is aimed to be modular_.
- Being a standalone SSH server/client, _this project is aimed at providing a library to build over the SSH protocol, not a complete implementation_.
