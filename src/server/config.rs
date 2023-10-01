use futures_time::time::Duration;
use ssh_key::PrivateKey;
use ssh_packet::Id;

#[derive(Debug)]
pub struct Config {
    pub id: Id,
    pub keys: Vec<PrivateKey>,
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: Id::v2(
                concat!(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                None::<&str>,
            ),
            keys: vec![],
            timeout: Duration::from_secs(3),
        }
    }
}
