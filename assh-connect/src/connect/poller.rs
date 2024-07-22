use assh::{side::Side, Pipe, Session};
use futures::{future::BoxFuture, task, FutureExt, Sink, Stream};
use ssh_packet::Packet;

use crate::Result;

type SendFut<IO, S> = BoxFuture<'static, (assh::Result<()>, Box<Session<IO, S>>)>;
type RecvFut<IO, S> = BoxFuture<'static, (assh::Result<Packet>, Box<Session<IO, S>>)>;

enum State<IO: Pipe, S: Side> {
    /// Idling and waiting for tasks.
    Idle(Box<Session<IO, S>>),

    /// Polling to send a packet.
    Sending(SendFut<IO, S>),

    /// Polling to recv a packet.
    Recving(RecvFut<IO, S>),
}

pub struct Poller<IO: Pipe, S: Side> {
    inner: State<IO, S>,
}

impl<IO, S> From<Session<IO, S>> for Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn from(session: Session<IO, S>) -> Self {
        Self {
            inner: State::Idle(session.into()),
        }
    }
}

impl<IO, S> Sink<Packet> for Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    type Error = assh::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        match &mut self.inner {
            State::Sending(fut) => {
                let (result, session) = futures::ready!(fut.poll_unpin(cx));

                self.inner = State::Idle(session);
                result?;

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            State::Recving(_) => {
                tracing::warn!("Busy waiting on sender in Poller::poll_ready");

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            _ => task::Poll::Ready(Ok(())),
        }
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
        replace_with::replace_with_or_abort(&mut self.inner, |inner| {
            match inner {
                State::Idle(mut session) => {
                    State::Sending(async move { (session.send(item).await, session) }.boxed())
                }

                // This is a genuine programming error from us if this happens,
                // which makes sense to panic!() to ensure test failure.
                #[allow(clippy::panic)]
                _ => {
                    panic!("Called `Sink::start_send` without calling `Sink::poll_ready` before");
                }
            }
        });

        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

impl<IO, S> Stream for Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    type Item = assh::Result<Packet>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Self::Item>> {
        replace_with::replace_with_or_abort_and_return(
            &mut self.as_mut().inner,
            |inner| match inner {
                State::Idle(mut session) => {
                    let mut fut = session.readable().boxed();

                    if fut.poll_unpin(cx).is_ready() {
                        drop(fut);

                        cx.waker().wake_by_ref();
                        (
                            task::Poll::Pending,
                            State::Recving(async move { (session.recv().await, session) }.boxed()),
                        )
                    } else {
                        drop(fut);

                        (task::Poll::Pending, State::Idle(session))
                    }
                }
                State::Recving(mut fut) => {
                    if let task::Poll::Ready((result, session)) = fut.as_mut().poll_unpin(cx) {
                        (
                            task::Poll::Ready(match result {
                                Err(assh::Error::Disconnected(_)) => None,
                                item => Some(item),
                            }),
                            State::Idle(session),
                        )
                    } else {
                        (task::Poll::Pending, State::Recving(fut))
                    }
                }
                State::Sending(mut fut) => {
                    if let task::Poll::Ready((result, session)) = fut.as_mut().poll_unpin(cx) {
                        (
                            match result {
                                Err(assh::Error::Disconnected(_)) => task::Poll::Ready(None),
                                Err(err) => task::Poll::Ready(Some(Err(err))),
                                Ok(_) => {
                                    cx.waker().wake_by_ref();
                                    task::Poll::Pending
                                }
                            },
                            State::Idle(session),
                        )
                    } else {
                        (task::Poll::Pending, State::Sending(fut))
                    }
                }
            },
        )
    }
}
