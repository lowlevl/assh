#![doc = concat!(
    "[![docs.rs](https://img.shields.io/docsrs/", env!("CARGO_PKG_NAME"), ")](https://docs.rs/", env!("CARGO_PKG_NAME"), ")",
    " ",
    "[![crates.io](https://img.shields.io/crates/l/", env!("CARGO_PKG_NAME"), ")](https://crates.io/crates/", env!("CARGO_PKG_NAME"), ")"
)]
#![doc = ""]
#![doc = env!("CARGO_PKG_DESCRIPTION")]

const SERVICE_NAME: &str = "ssh-userauth";
const CONNECTION_SERVICE_NAME: &str = "ssh-connection";

mod methods;
pub use methods::Methods;

pub mod client;
pub mod server;
