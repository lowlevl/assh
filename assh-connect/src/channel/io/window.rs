use std::sync::atomic::{AtomicU32, Ordering};

use futures::task;

pub struct LocalWindow {
    inner: AtomicU32,
}

impl LocalWindow {
    const INITIAL_WINDOW_SIZE: u32 = 64 * crate::MAXIMUM_PACKET_SIZE;
    const FLOATING_THRESHOLD: u32 = Self::INITIAL_WINDOW_SIZE / 2;

    pub fn new() -> Self {
        Self {
            inner: Self::INITIAL_WINDOW_SIZE.into(),
        }
    }

    pub fn remaining(&self) -> u32 {
        self.inner.load(Ordering::Relaxed)
    }

    pub fn consume(&self, size: u32) {
        self.inner.fetch_sub(size, Ordering::Relaxed);
    }

    pub fn adjust(&self) -> Option<u32> {
        let previous = self
            .inner
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |window| {
                if window < Self::FLOATING_THRESHOLD {
                    Some(Self::INITIAL_WINDOW_SIZE)
                } else {
                    None
                }
            })
            .ok();

        previous.map(|previous| Self::INITIAL_WINDOW_SIZE - previous)
    }
}

pub struct RemoteWindow {
    inner: AtomicU32,
    waker: task::AtomicWaker,
}

impl RemoteWindow {
    pub fn new(size: u32) -> Self {
        Self {
            inner: size.into(),
            waker: Default::default(),
        }
    }

    pub fn adjust(&self, size: u32) {
        self.inner.fetch_add(size, Ordering::Release);
        self.waker.wake();
    }

    fn try_reserve(&self, mut amount: u32) -> Option<u32> {
        self.inner
            .fetch_update(Ordering::Release, Ordering::Acquire, |window| {
                if amount <= window {
                    Some(window - amount)
                } else {
                    amount = window;

                    if amount > 0 {
                        Some(0)
                    } else {
                        None
                    }
                }
            })
            .ok();

        if amount > 0 {
            Some(amount)
        } else {
            None
        }
    }

    pub fn poll_reserve(&self, cx: &mut task::Context, amount: u32) -> task::Poll<u32> {
        if let Some(size) = self.try_reserve(amount) {
            task::Poll::Ready(size)
        } else {
            // TODO: Does this cause busy waiting ? Is it necessary ? Maybe host a collection of wakers.
            self.waker.wake();

            self.waker.register(cx.waker());
            task::Poll::Pending
        }
    }
}
