use std::{
    collections::VecDeque,
    num::NonZeroU32,
    sync::atomic::{AtomicBool, Ordering},
    task,
};

use dashmap::DashMap;
use futures::{lock::Mutex, FutureExt};

use super::LocalWindow;

pub struct Multiplexer {
    window: LocalWindow,
    eof: AtomicBool,

    shared: Mutex<VecDeque<(Option<NonZeroU32>, Vec<u8>)>>,
    wakers: DashMap<Option<NonZeroU32>, task::Waker>,
}

impl Multiplexer {
    pub fn new(window: LocalWindow) -> Self {
        Self {
            window,

            eof: Default::default(),
            shared: Default::default(),
            wakers: Default::default(),
        }
    }

    pub async fn publish(&self, ext: Option<NonZeroU32>, data: Vec<u8>) {
        self.shared.lock().await.push_front((ext, data));

        self.eof.store(false, Ordering::Relaxed);

        if let Some((_, waker)) = self.wakers.remove(&ext) {
            waker.wake()
        }
    }

    pub async fn eof(&self) {
        self.eof.store(true, Ordering::Relaxed);

        self.wakers
            .iter()
            .for_each(|refer| refer.value().wake_by_ref())
    }

    pub fn window(&self) -> &LocalWindow {
        &self.window
    }

    pub fn poll_data(
        &self,
        cx: &mut task::Context,
        ext: Option<NonZeroU32>,
    ) -> task::Poll<Vec<u8>> {
        let mut queue = futures::ready!(self.shared.lock().poll_unpin(cx));

        match queue.back() {
            // The data in the FIFO is for our task, pop it and return it.
            Some((typ, _)) if typ == &ext => {
                let (_, data) = queue
                    .pop_back()
                    .expect("Queue emptied while still holding the lock");

                self.window.consume(data.len() as u32);

                task::Poll::Ready(data)
            }
            Some((typ, _)) => {
                // The data in the FIFO is for another task, wake the task.
                if let Some((_, waker)) = self.wakers.remove(typ) {
                    waker.wake();
                } else {
                    // The data in the FIFO is not awaited by any task, drop it.
                    let (_, data) = queue
                        .pop_back()
                        .expect("Queue emptied while still holding the lock");

                    self.window.consume(data.len() as u32);

                    tracing::warn!(
                        "Dropped unhandled data block of size `{}` for stream {ext:?}",
                        data.len()
                    );
                }

                self.wakers.insert(ext, cx.waker().clone());
                task::Poll::Pending
            }
            // The data in the FIFO is empty and the peer reported EOF.
            None if self.eof.load(Ordering::Relaxed) => task::Poll::Ready(vec![]),
            // The data in the FIFO is empty.
            None => {
                self.wakers.insert(ext, cx.waker().clone());
                task::Poll::Pending
            }
        }
    }
}
