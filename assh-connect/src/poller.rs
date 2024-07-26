use std::collections::VecDeque;

use assh::{side::Side, Pipe, Session};
use futures::{future::BoxFuture, task, FutureExt, Sink, Stream, StreamExt};
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
    buffer: Option<Packet>,
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
            buffer: Default::default(),
        }
    }
}

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
            if let Some(result) = futures::ready!(self.poll_next_unpin(cx)) {
                self.buffer = Some(result?);
            }
        }

        task::Poll::Ready(Ok(&mut self.buffer))
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
        tracing::trace!(
            "Queueing message in the sender of type ^{:#x}",
            item.payload[0]
        );

        self.queue.push_back(item);

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
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

                if let Some(item) = self.queue.pop_front() {
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
                // TODO: Fix this with an AtomicWaker.
                tracing::warn!("Busy waiting in Poller::poll_flush");

                cx.waker().wake_by_ref();
                task::Poll::Pending
            }
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

                tracing::trace!(
                    "Polled incoming data from peer: ^{:x?}",
                    result.as_ref().map(|packet| packet.payload[0])
                );

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
