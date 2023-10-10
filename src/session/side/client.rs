use futures_time::time::Duration;
use ssh_packet::Id;

/// A session _client_-side configuration.
pub struct Client {
    pub id: Id,
    pub timeout: Duration,
}
