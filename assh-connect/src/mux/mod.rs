use assh::{side::Side, Pipe, Session};
use dashmap::DashMap;
use futures::{lock::Mutex, task, FutureExt};
use ssh_packet::{binrw, connect, IntoPacket, Packet};

mod interest;
pub use interest::Interest;

mod poller;
use poller::Poller;

pub mod slots;
use slots::{Lease, Slots};

const CHANNEL_MAX_COUNT: usize = 8;

pub struct Mux<IO: Pipe, S: Side> {
    queue: flume::Sender<Packet>,
    poller: Mutex<Poller<IO, S>>,
    interests: DashMap<Interest, task::AtomicWaker>,
    pub(crate) channels: Slots<u32, CHANNEL_MAX_COUNT>,
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
            channels: Default::default(),
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

    pub fn register_scoped(&self, interest: Interest) -> impl Drop + '_ {
        self.register(interest);

        defer::defer(move || self.unregister(&interest))
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

    pub fn poll_interest<T>(
        &self,
        cx: &mut task::Context,
        interest: &Interest,
    ) -> task::Poll<Option<assh::Result<T>>>
    where
        T: for<'args> binrw::BinRead<Args<'args> = ()> + binrw::meta::ReadEndian,
    {
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

                    task::Poll::Ready(Some(Ok(packet.to().expect(
                        "Internal programming error: Polled with diverging `interest` and `T`",
                    ))))
                } else {
                    match self.interests.get(&packet_interest).as_deref() {
                        Some(waker) => {
                            tracing::trace!("{interest:?} != {packet_interest:?}: Storing packet and waking task");

                            *buffer = Some(packet);
                            waker.wake();

                            task::Poll::Pending
                        }
                        None => {
                            if let Ok(message) = packet.to::<connect::GlobalRequest>() {
                                tracing::debug!(
                                    "{packet_interest:?}: Rejectected an unhandled `GlobalRequest`"
                                );

                                if *message.want_reply {
                                    crate::global_request::GlobalRequest::rejected(self);
                                }
                            } else if let Ok(message) = packet.to::<connect::ChannelOpen>() {
                                tracing::debug!(
                                    "{packet_interest:?}: Rejectected an unhandled `ChannelOpenRequest`"
                                );

                                crate::channel_open::ChannelOpen::rejected(
                                    self,
                                    message.sender_channel,
                                    None,
                                    None,
                                );
                            } else if let Ok(message) = packet.to::<connect::ChannelRequest>() {
                                tracing::debug!("{packet_interest:?}: Rejectected an unhandled `ChannelRequest`");

                                if *message.want_reply {
                                    if let Some(id) = self
                                        .channels
                                        .get(message.recipient_channel as usize)
                                        .as_ref()
                                        .map(Lease::value)
                                    {
                                        crate::channel::request::Request::rejected(self, *id);
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    "!{packet_interest:?}: Dropping {}bytes, unregistered interest",
                                    packet.len()
                                );
                            }

                            cx.waker().wake_by_ref();
                            task::Poll::Pending
                        }
                    }
                }
            }
        }
    }

    pub fn feed(&self, item: impl IntoPacket) {
        self.queue.send(item.into_packet()).ok();
    }

    pub fn poll_flush(&self, cx: &mut task::Context) -> task::Poll<assh::Result<()>> {
        let mut poller = futures::ready!(self.poller.lock().poll_unpin(cx));

        poller.poll_flush(cx)
    }

    pub async fn flush(&self) -> assh::Result<()> {
        futures::future::poll_fn(|cx| self.poll_flush(cx)).await
    }

    pub async fn send(&self, item: impl IntoPacket) -> assh::Result<()> {
        self.feed(item);
        self.flush().await
    }
}
