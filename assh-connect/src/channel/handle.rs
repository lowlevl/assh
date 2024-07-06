use std::sync::Arc;

use flume::Sender;

use super::{Multiplexer, RemoteWindow};
use crate::connect::messages;

pub struct Handle {
    pub control: Sender<messages::Control>,
    pub window: Arc<RemoteWindow>,
    pub mux: Arc<Multiplexer>,
}
