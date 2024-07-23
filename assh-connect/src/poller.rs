use std::collections::VecDeque;

use assh::{side::Side, Pipe, Session};
use futures::{future::BoxFuture, task, FutureExt, Sink, Stream};
use ssh_packet::Packet;

use crate::Result;

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
    queue: VecDeque<Packet>,
}

impl<IO, S> From<Session<IO, S>> for Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn from(session: Session<IO, S>) -> Self {
        Self {
            state: State::Idle(Some(session.into())),
            queue: Default::default(),
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
        self: std::pin::Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        // We are always ready to receive a Packet in the sink,
        // because it is backed with a FIFO queue to hold pending packets.

        task::Poll::Ready(Ok(()))
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
        self.queue.push_front(item);

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        let empty_queue = self.queue.is_empty();

        match self.state {
            State::Idle(ref mut session) if !empty_queue => {
                let Some(mut session) = session.take() else {
                    unreachable!()
                };

                if let Some(item) = self.queue.pop_back() {
                    self.state =
                        State::Sending(async move { (session.send(item).await, session) }.boxed());
                } else {
                    unreachable!()
                }

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            State::Sending(ref mut fut) => {
                let (result, session) = futures::ready!(fut.poll_unpin(cx));

                self.state = State::Idle(Some(session));
                result?;

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            State::Recving(_) => {
                tracing::warn!("Busy waiting in Poller::poll_flush");

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
            _ => task::Poll::Ready(Ok(())),
        }
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
        if !matches!(self.state, State::Recving(_)) {
            futures::ready!(self.as_mut().poll_flush(cx))?;
        }

        match &mut self.state {
            State::Recving(fut) => {
                let (result, session) = futures::ready!(fut.poll_unpin(cx));

                self.state = State::Idle(Some(session));

                task::Poll::Ready(match result {
                    Err(assh::Error::Disconnected(_)) => None,
                    other => Some(other),
                })
            }
            State::Idle(session) => {
                let Some(mut session) = session.take() else {
                    unreachable!()
                };

                if session.readable().boxed().poll_unpin(cx).is_ready() {
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
