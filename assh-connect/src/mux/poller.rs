use assh::{Pipe, Session, side::Side};
use futures::{FutureExt, future::BoxFuture, task};
use ssh_packet::Packet;

type SendFut<IO, S> = BoxFuture<'static, (assh::Result<()>, Box<Session<IO, S>>)>;
type RecvFut<IO, S> = BoxFuture<'static, (assh::Result<Packet>, Box<Session<IO, S>>)>;

enum State<IO: Pipe, S: Side> {
    /// Idling and waiting for tasks.
    Idle(Option<Box<Session<IO, S>>>),

    /// Polling to send a packet.
    Sending(SendFut<IO, S>),

    /// Polling to recv a packet.
    Recving(RecvFut<IO, S>),
}

pub struct Poller<IO: Pipe, S: Side> {
    state: State<IO, S>,

    /// Messages awaiting to be sent to the peer.
    queue: flume::Receiver<Packet>,

    /// Message awaiting to be popped by the local asynchronous tasks.
    buffer: Option<Packet>,
}

impl<IO, S> Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub fn new(session: Session<IO, S>) -> (Self, flume::Sender<Packet>) {
        let (tx, rx) = flume::unbounded();

        (
            Self {
                state: State::Idle(Some(session.into())),

                queue: rx,
                buffer: Default::default(),
            },
            tx,
        )
    }
}

/// Methods used to _receive_ messages from the [`Session`].
impl<IO, S> Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub fn poll_peek(
        &mut self,
        cx: &mut task::Context,
    ) -> task::Poll<assh::Result<&mut Option<Packet>>> {
        if self.buffer.is_none() {
            self.buffer = futures::ready!(self.poll_next(cx)).transpose()?;
        }

        task::Poll::Ready(Ok(&mut self.buffer))
    }

    fn poll_next(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<assh::Result<Packet>>> {
        if !matches!(self.state, State::Recving(_)) {
            // NOTE: We ignore errors there because while flushing before receiving is often necessary,
            // errors there shouldn't bubble up to the read side; e.g. sometimes messages are still
            // in the pipe even though it has been closed for writing.
            futures::ready!(self.poll_flush(cx)).ok();
        }

        match &mut self.state {
            State::Recving(fut) => {
                let (result, session) = futures::ready!(fut.poll_unpin(cx));

                tracing::trace!(
                    "Polled incoming data from peer: ^{:x?}",
                    result.as_ref().map(|packet| packet[0])
                );

                self.state = State::Idle(Some(session));

                task::Poll::Ready(Some(result))
            }

            State::Idle(session) => {
                let Some(mut session) = session.take() else {
                    unreachable!()
                };

                if session.readable().boxed_local().poll_unpin(cx).is_ready() {
                    self.state =
                        State::Recving(async move { (session.recv().await, session) }.boxed());

                    cx.waker().wake_by_ref();
                    task::Poll::Pending
                } else {
                    self.state = State::Idle(Some(session));

                    task::Poll::Pending
                }
            }

            _ => unreachable!(),
        }
    }
}

/// Methods used to _send_ messages from the [`Session`].
impl<IO, S> Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    pub fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> task::Poll<assh::Result<()>> {
        match &mut self.state {
            State::Sending(fut) => {
                let (result, session) = futures::ready!(fut.poll_unpin(cx));

                self.state = State::Idle(Some(session));
                result?;

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }

            State::Idle(session) => {
                let Some(mut session) = session.take() else {
                    unreachable!()
                };

                if let Ok(item) = self.queue.try_recv() {
                    self.state =
                        State::Sending(async move { (session.send(item).await, session) }.boxed());

                    cx.waker().wake_by_ref();
                    task::Poll::Pending
                } else {
                    self.state = State::Idle(Some(session));

                    task::Poll::Ready(Ok(()))
                }
            }

            State::Recving(_) => {
                // TODO: (optimization) Fix this with an AtomicWaker ?
                tracing::warn!("Busy waiting in Poller::poll_flush");

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
        }
    }
}
