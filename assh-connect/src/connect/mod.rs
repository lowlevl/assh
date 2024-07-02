//! Facilities to interract with the SSH _connect_ protocol.

use std::{collections::HashMap, convert::Infallible};

use assh::{side::Side, Session};
use flume::{Receiver, Sender};
use futures::{AsyncBufRead, AsyncWrite, FutureExt};
use ssh_packet::{connect, Packet};

use crate::{channel, Result};

pub(super) mod messages;

pub mod channel_open;
pub mod global_request;

#[doc(no_inline)]
pub use connect::{ChannelOpenContext, ChannelOpenFailureReason, GlobalRequestContext};

/// A wrapper around a [`Session`] to interract with the connect layer.
pub struct Connect<'s, IO, S, G = (), C = ()> {
    session: &'s mut Session<IO, S>,

    on_global_request: G,
    on_channel_open: C,

    outgoing: (Sender<Packet>, Receiver<Packet>),
    channels: HashMap<u32, channel::Handle>,
}

impl<'s, IO, S> Connect<'s, IO, S> {
    /// Create a wrapper around the `session` to handle the connect layer.
    pub(super) fn new(session: &'s mut Session<IO, S>) -> Self {
        Self {
            session,

            on_global_request: (),
            on_channel_open: (),

            outgoing: flume::unbounded(),
            channels: Default::default(),
        }
    }
}

impl<'s, IO, S, G, C> Connect<'s, IO, S, G, C>
where
    IO: AsyncBufRead + AsyncWrite + Unpin,
    S: Side,
    G: global_request::Hook,
    C: channel_open::Hook,
{
    fn local_id(&self) -> u32 {
        self.channels
            .keys()
            .max()
            .map(|x| x + 1)
            .unwrap_or_default()
    }

    /// Make a _global request_ with the provided `context`.
    pub async fn global_request(
        &mut self,
        context: GlobalRequestContext,
    ) -> Result<global_request::GlobalRequest> {
        let with_port = matches!(context, GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

        self.session
            .send(&connect::GlobalRequest {
                want_reply: true.into(),
                context,
            })
            .await?;

        let packet = self.session.recv().await?;
        if let Ok(connect::RequestFailure) = packet.to() {
            Ok(global_request::GlobalRequest::Rejected)
        } else if with_port {
            if let Ok(connect::ForwardingSuccess { bound_port }) = packet.to() {
                Ok(global_request::GlobalRequest::AcceptedPort(bound_port))
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else if let Ok(connect::RequestSuccess) = packet.to() {
            Ok(global_request::GlobalRequest::Accepted)
        } else {
            Err(assh::Error::UnexpectedMessage.into())
        }
    }

    /// Register the hook for _global requests_.
    ///
    /// # Note:
    ///
    /// Blocking the hook will block the main [`Self::spin`] loop,
    /// which will cause new global requests and channels to stop
    /// being processed, as well as interrupt channel I/O.
    pub fn on_global_request(
        self,
        hook: impl global_request::Hook,
    ) -> Connect<'s, IO, S, impl global_request::Hook, C> {
        let Self {
            session,

            on_channel_open: on_channel,
            on_global_request: _,

            outgoing,
            channels,
        } = self;

        Connect {
            session,

            on_channel_open: on_channel,
            on_global_request: hook,

            outgoing,
            channels,
        }
    }

    /// Request a new _channel_ with the provided `context`.
    pub async fn channel_open(
        &mut self,
        context: ChannelOpenContext,
    ) -> Result<channel_open::ChannelOpen> {
        let local_id = self.local_id();

        self.session
            .send(&connect::ChannelOpen {
                sender_channel: local_id,
                initial_window_size: channel::LocalWindow::INITIAL_WINDOW_SIZE,
                maximum_packet_size: channel::LocalWindow::MAXIMUM_PACKET_SIZE,
                context,
            })
            .await?;

        let packet = self.session.recv().await?;

        if let Ok(open_failure) = packet.to::<connect::ChannelOpenFailure>() {
            if open_failure.recipient_channel == local_id {
                Ok(channel_open::ChannelOpen::Rejected {
                    reason: open_failure.reason,
                    message: open_failure.description.into_string(),
                })
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else if let Ok(open_confirmation) = packet.to::<connect::ChannelOpenConfirmation>() {
            if open_confirmation.recipient_channel == local_id {
                let (channel, handle) = channel::pair(
                    open_confirmation.recipient_channel,
                    open_confirmation.maximum_packet_size,
                    (
                        channel::LocalWindow::default(),
                        channel::RemoteWindow::from(open_confirmation.initial_window_size),
                    ),
                    self.outgoing.0.clone(),
                );

                self.channels.insert(local_id, handle);

                Ok(channel_open::ChannelOpen::Accepted(channel))
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else {
            Err(assh::Error::UnexpectedMessage.into())
        }
    }

    /// Register the hook for _channel open requests_.
    ///
    /// # Note:
    ///
    /// Blocking the hook will block the main [`Self::spin`] loop,
    /// which will cause new global requests and channels to stop
    /// being processed, as well as interrupt channel I/O.
    pub fn on_channel_open(
        self,
        hook: impl channel_open::Hook,
    ) -> Connect<'s, IO, S, G, impl channel_open::Hook> {
        let Self {
            session,

            on_channel_open: _,
            on_global_request,

            outgoing,
            channels,
        } = self;

        Connect {
            session,

            on_channel_open: hook,
            on_global_request,

            outgoing,
            channels,
        }
    }

    /// Spin up the connect protocol handling, with the registered hooks
    /// to fuel channel I/O and hooks with messages.
    pub async fn spin(mut self) -> Result<Infallible> {
        loop {
            futures::select! {
                msg = self.outgoing.1.recv_async() => {
                    #[allow(clippy::unwrap_used)] // Will never be disconnected, since this struct always hold a sender.
                    self.session.send(msg.unwrap()).await?;
                }
                res = self.session.readable().fuse() => {
                    res?;

                    self.rx().await?;
                }
            }
        }
    }

    async fn rx(&mut self) -> Result<()> {
        let packet = self.session.recv().await?;

        if let Ok(global_request) = packet.to::<connect::GlobalRequest>() {
            let with_port = matches!(global_request.context, GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);
            let outcome = self.on_global_request.on_request(global_request.context);

            if *global_request.want_reply {
                match outcome {
                    global_request::Outcome::Accept { bound_port } if with_port => {
                        self.session
                            .send(&connect::ForwardingSuccess { bound_port })
                            .await?;
                    }
                    global_request::Outcome::Accept { .. } => {
                        self.session.send(&connect::RequestSuccess).await?;
                    }
                    global_request::Outcome::Reject => {
                        self.session.send(&connect::RequestFailure).await?;
                    }
                }
            }
        } else if let Ok(channel_open) = packet.to::<connect::ChannelOpen>() {
            tracing::debug!(
                "Peer requested to open channel %{}: {:?}",
                channel_open.sender_channel,
                channel_open.context
            );

            let (channel, handle) = channel::pair(
                channel_open.sender_channel,
                channel_open.maximum_packet_size,
                (
                    channel::LocalWindow::default(),
                    channel::RemoteWindow::from(channel_open.initial_window_size),
                ),
                self.outgoing.0.clone(),
            );

            match self
                .on_channel_open
                .on_request(channel_open.context, channel)
            {
                channel_open::Outcome::Accept => {
                    let local_id = self.local_id();

                    self.session
                        .send(&connect::ChannelOpenConfirmation {
                            recipient_channel: channel_open.sender_channel,
                            sender_channel: local_id,
                            initial_window_size: channel::LocalWindow::INITIAL_WINDOW_SIZE,
                            maximum_packet_size: channel::LocalWindow::MAXIMUM_PACKET_SIZE,
                        })
                        .await?;

                    self.channels.insert(local_id, handle);

                    tracing::debug!(
                        "Channel opened as #{local_id}:%{}",
                        channel_open.sender_channel
                    );
                }
                channel_open::Outcome::Reject {
                    reason,
                    description,
                } => {
                    self.session
                        .send(&connect::ChannelOpenFailure {
                            recipient_channel: channel_open.sender_channel,
                            reason,
                            description,
                            language: Default::default(),
                        })
                        .await?;

                    tracing::debug!("Channel open refused for %{}", channel_open.sender_channel);
                }
            }
        } else if let Ok(channel_close) = packet.to::<connect::ChannelClose>() {
            tracing::debug!("Peer closed channel #{}", channel_close.recipient_channel);

            self.channels.remove(&channel_close.recipient_channel);
        } else if let Ok(window_adjust) = packet.to::<connect::ChannelWindowAdjust>() {
            if let Some(handle) = self.channels.get(&window_adjust.recipient_channel) {
                tracing::debug!(
                    "Peer adjusted window size by `{}` for channel %{}",
                    window_adjust.bytes_to_add,
                    window_adjust.recipient_channel
                );

                handle.windows.1.replenish(window_adjust.bytes_to_add);
            }
        } else if let Ok(data) = packet.to::<messages::Data>() {
            if let Some(handle) = self.channels.get(data.recipient_channel()) {
                if let Some(sender) = handle.streams.get(&data.data_type()) {
                    // TODO: Handle dropped streams
                    sender.send_async(data.data()).await.ok();
                } else {
                    handle.windows.0.consume(data.data().len() as u32);
                }
            }
        } else if let Ok(control) = packet.to::<messages::Control>() {
            if let Some(handle) = self.channels.get(control.recipient_channel()) {
                // TODO: Handle closed channels
                handle.control.send_async(control).await.ok();
            } else {
                tracing::warn!(
                    "Received a message for closed channel #{}",
                    control.recipient_channel()
                );
            }
        } else {
            tracing::warn!(
                "Received an unhandled packet from peer of length `{}` bytes",
                packet.payload.len()
            );

            // TODO: Send back an `Unimplemented` packet if necessary or pertinent
        }

        Ok(())
    }
}
