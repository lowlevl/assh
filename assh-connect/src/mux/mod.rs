use assh::{side::Side, Pipe, Session};
use dashmap::DashMap;
use futures::{lock::Mutex, task, FutureExt};
use ssh_packet::{IntoPacket, Packet};

mod interest;
pub use interest::Interest;

mod poller;
use poller::Poller;

pub struct Mux<IO: Pipe, S: Side> {
    queue: flume::Sender<Packet>,
    poller: Mutex<Poller<IO, S>>,
    interests: DashMap<Interest, task::AtomicWaker>,
}

impl<IO, S> From<Session<IO, S>> for Mux<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn from(session: Session<IO, S>) -> Self {
        let (poller, queue) = Poller::new(session);

        Self {
            queue,
            poller: poller.into(),
            interests: Default::default(),
        }
    }
}

impl<IO, S> Mux<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub fn register(&self, interest: Interest) {
        // This is a genuine programming error from the user of the crate,
        // and could cause all sorts of runtime inconsistencies.
        #[allow(clippy::panic)]
        if self
            .interests
            .insert(interest, Default::default())
            .is_some()
        {
            panic!("Unable to register multiple concurrent interests for `{interest:?}`");
        }

        tracing::trace!("Registered interest for `{interest:?}`");
    }

    pub fn unregister(&self, interest: &Interest) {
        if let Some((interest, waker)) = self.interests.remove(interest) {
            tracing::trace!("Unregistered interest for `{interest:?}`");

            // Wake unregistered tasks to signal them to finish.
            waker.wake();
        }
    }

    pub fn unregister_if(&self, filter: impl Fn(&Interest) -> bool) {
        // NOTE: We collect here to remove reference to the DashMap
        // which would deadlock on calls to `remove` in `Self::unregister`.
        for interest in self
            .interests
            .iter()
            .map(|interest| *interest.key())
            .filter(filter)
            .collect::<Vec<_>>()
        {
            self.unregister(&interest);
        }
    }

    pub fn poll_interest(
        &self,
        cx: &mut task::Context,
        interest: &Interest,
    ) -> task::Poll<Option<assh::Result<Packet>>> {
        tracing::trace!("Polled with interest `{interest:?}`");

        if self
            .interests
            .get(interest)
            .as_deref()
            .map(|waker| waker.register(cx.waker()))
            .is_none()
        {
            tracing::trace!("{interest:?}: Polled for unregistered interest, returning `None`");

            return task::Poll::Ready(None);
        }

        let mut poller = futures::ready!(self.poller.lock().poll_unpin(cx));
        let buffer = futures::ready!(poller.poll_peek(cx))?;

        match buffer.take() {
            None => {
                tracing::trace!(
                    "{interest:?}: Receiver dead, unregistering all interests, waking up tasks"
                );

                // Optimization for woken up tasks to return early `Ready(None)`.
                self.unregister_if(|_| true);

                task::Poll::Ready(None)
            }
            Some(packet) => {
                let Some(packet_interest) = Interest::parse(&packet) else {
                    return task::Poll::Ready(Some(Err(assh::Error::UnexpectedMessage)));
                };

                if interest == &packet_interest {
                    tracing::trace!("{interest:?}: Matched, popping packet");

                    task::Poll::Ready(Some(Ok(packet)))
                } else {
                    match self.interests.get(&packet_interest).as_deref() {
                        Some(waker) => {
                            tracing::trace!("{interest:?} != {packet_interest:?}: Storing packet and waking task");

                            *buffer = Some(packet);
                            waker.wake();

                            task::Poll::Pending
                        }
                        None => {
                            tracing::warn!(
                                "!{packet_interest:?}: Dropping {}bytes, unregistered interest",
                                packet.payload.len()
                            );

                            // TODO: Respond to unhandled `GlobalRequest`, `ChannelOpenRequest` & `ChannelRequest` that *want_reply*.

                            cx.waker().wake_by_ref();
                            task::Poll::Pending
                        }
                    }
                }
            }
        }
    }

    pub fn push(&self, item: impl IntoPacket) {
        self.queue.send(item.into_packet()).ok();
    }

    pub fn poll_flush(&self, cx: &mut task::Context) -> task::Poll<assh::Result<()>> {
        let mut poller = futures::ready!(self.poller.lock().poll_unpin(cx));

        poller.poll_flush(cx)
    }

    pub async fn send(&self, item: impl IntoPacket) -> assh::Result<()> {
        self.push(item);

        futures::future::poll_fn(|cx| self.poll_flush(cx)).await
    }
}
