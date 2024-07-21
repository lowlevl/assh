use std::sync::Arc;

use assh::{side::Side, Pipe, Session};
use either::Either;
use futures::{future::BoxFuture, lock::Mutex, task, FutureExt, Sink, Stream};
use ssh_packet::Packet;

use crate::Result;

pub struct Poller<IO: Pipe, S: Side> {
    session: Arc<Mutex<Session<IO, S>>>,

    // TODO: Investigate the feasibility of removing those two boxes and 'static lifetimes
    send: Either<Option<Packet>, BoxFuture<'static, assh::Result<()>>>,
    recv: BoxFuture<'static, assh::Result<Packet>>,
}

impl<IO, S> From<Session<IO, S>> for Poller<IO, S>
where
    IO: Pipe,
    S: Side,
{
    fn from(session: Session<IO, S>) -> Self {
        let session: Arc<_> = Mutex::new(session).into();

        Self {
            session: session.clone(),
            send: Either::Left(None),
            recv: async move { session.lock_owned().await.recv().await }.boxed(),
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
            Either::Right(fut) => {
                futures::ready!(fut.poll_unpin(cx))?;

                self.send = Either::Left(None);
                self.poll_flush(cx)
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
        let recvd = futures::ready!(self.recv.poll_unpin(cx));

        // Queue future for the next `poll_next` calls
        let session = self.session.clone();
        self.recv = async move { session.lock_owned().await.recv().await }.boxed();

        match recvd {
            Err(assh::Error::Disconnected(_)) => task::Poll::Ready(None),
            recvd => task::Poll::Ready(Some(recvd)),
        }
    }
}
