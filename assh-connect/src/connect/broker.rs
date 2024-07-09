use std::sync::Arc;

use assh::{side::Side, Pipe, Session};
use either::Either;
use futures::{future::BoxFuture, lock::Mutex, task, FutureExt, Sink, Stream};
use ssh_packet::Packet;

use crate::Result;

pub struct Broker<'s, IO: Pipe, S: Side> {
    session: Arc<Mutex<&'s mut Session<IO, S>>>,

    send: Either<Option<Packet>, BoxFuture<'s, assh::Result<()>>>,
    recv: BoxFuture<'s, assh::Result<Packet>>,
}

impl<'s, IO, S> Sink<Packet> for Broker<'s, IO, S>
where
    IO: Pipe,
    S: Side,
{
    type Error = assh::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
        // This is a genuine programming error from us if this happens,
        // which makes sense to panic!() to ensure test failure.
        #[allow(clippy::panic)]
        if !matches!(self.send, Either::Left(None)) {
            panic!("Called `Sink::start_send` without calling `Sink::poll_ready` before");
        }

        self.send = Either::Left(Some(item));

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        match self
            .send
            .as_mut()
            .left_and_then(|option| Either::Left(option.take()))
        {
            Either::Left(None) => task::Poll::Ready(Ok(())),
            Either::Left(Some(item)) => {
                let session = self.session.clone();
                self.send = Either::Right(
                    async move { session.lock_owned().await.send(item).await }.boxed(),
                );

                self.poll_flush(cx)
            }
            Either::Right(fut) => fut.poll_unpin(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

impl<'s, IO, S> Stream for Broker<'s, IO, S>
where
    IO: Pipe,
    S: Side,
{
    type Item = assh::Result<Packet>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Self::Item>> {
        let item = futures::ready!(self.recv.poll_unpin(cx))?;

        let session = self.session.clone();
        self.recv = async move { session.lock_owned().await.recv().await }.boxed();

        task::Poll::Ready(Some(Ok(item)))
    }
}

impl<'s, IO, S> From<&'s mut Session<IO, S>> for Broker<'s, IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn from(session: &'s mut Session<IO, S>) -> Self {
        let session: Arc<_> = Mutex::new(session).into();

        Self {
            session: session.clone(),
            send: Either::Left(None),
            recv: async move { session.lock_owned().await.recv().await }.boxed(),
        }
    }
}
