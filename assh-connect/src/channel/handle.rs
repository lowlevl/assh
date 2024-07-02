use std::{num::NonZeroU32, sync::Arc};

use dashmap::DashMap;
use flume::Sender;

use super::{LocalWindow, RemoteWindow};
use crate::connect::messages;

pub struct Handle {
    pub control: Sender<messages::Control>,
    pub streams: Arc<DashMap<Option<NonZeroU32>, Sender<Vec<u8>>>>,
    pub windows: (Arc<LocalWindow>, Arc<RemoteWindow>),
}
