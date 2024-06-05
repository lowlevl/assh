//! Facilities to interract with the SSH _connect_ protocol.

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use assh::{side::Side, Session};
use futures::{AsyncBufRead, AsyncWrite, FutureExt};
use ssh_packet::connect;

use crate::{
    channel::{Channel, Msg},
    Result, INITIAL_WINDOW_SIZE, MAXIMUM_PACKET_SIZE,
};

pub mod channel;
pub mod global_request;

/// The response to a _global request_.
#[derive(Debug)]
pub enum GlobalRequest {
    /// _Accepted_ global request.
    Accepted,

    /// _Accepted_ global request, with a bound port.
    AcceptedPort(u32),

    /// _Rejected_ the global request.
    Rejected,
}

/// The response to a _channel open request_.
#[derive(Debug)]
pub enum ChannelOpen {
    /// _Accepted_ the channel open request.
    Accepted(Channel),

    /// _Rejected_ the channel open request.
    Rejected {
        /// The reason for failure.
        reason: connect::ChannelOpenFailureReason,

        /// A textual message to acompany the reason.
        message: String,
    },
}

struct ChannelDef {
    sender: flume::Sender<Msg>,
    remote_window_size: Arc<AtomicU32>,
}

/// A wrapper around a [`Session`] to interract with the connect layer.
pub struct Connect<'s, IO, S, G = (), C = ()> {
    session: &'s mut Session<IO, S>,
    channels: HashMap<u32, ChannelDef>,

    sender: flume::Sender<Msg>,
    receiver: flume::Receiver<Msg>,

    on_global_request: G,
    on_channel_open: C,
}

impl<'s, IO, S> Connect<'s, IO, S> {
    /// Create a wrapper around the `session` to handle the connect layer.
    pub(super) fn new(session: &'s mut Session<IO, S>) -> Self {
        let (sender, receiver) = flume::unbounded();

        Self {
            session,
            channels: Default::default(),

            sender,
            receiver,

            on_global_request: (),
            on_channel_open: (),
        }
    }
}

impl<'s, IO, S, G, C> Connect<'s, IO, S, G, C>
where
    IO: AsyncBufRead + AsyncWrite + Unpin,
    S: Side,
    G: global_request::Hook,
    C: channel::Hook,
{
    /// Make a _global request_ with the provided `context`.
    pub async fn global_request(
        &mut self,
        context: connect::GlobalRequestContext,
    ) -> Result<GlobalRequest> {
        let with_port = matches!(context, connect::GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);

        self.session
            .send(&connect::GlobalRequest {
                want_reply: true.into(),
                context,
            })
            .await?;

        let packet = self.session.recv().await?;
        if let Ok(connect::RequestFailure) = packet.to() {
            Ok(GlobalRequest::Rejected)
        } else if with_port {
            if let Ok(connect::ForwardingSuccess { bound_port }) = packet.to() {
                Ok(GlobalRequest::AcceptedPort(bound_port))
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else if let Ok(connect::RequestSuccess) = packet.to() {
            Ok(GlobalRequest::Accepted)
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
            channels,

            sender,
            receiver,

            on_channel_open: on_channel,
            on_global_request: _,
        } = self;

        Connect {
            session,
            channels,

            sender,
            receiver,

            on_channel_open: on_channel,
            on_global_request: hook,
        }
    }

    /// Request a new _channel_ with the provided `context`.
    pub async fn channel_open(
        &mut self,
        context: connect::ChannelOpenContext,
    ) -> Result<ChannelOpen> {
        let local_id = self
            .channels
            .keys()
            .max()
            .map(|x| x + 1)
            .unwrap_or_default();

        self.session
            .send(&connect::ChannelOpen {
                sender_channel: local_id,
                initial_window_size: INITIAL_WINDOW_SIZE,
                maximum_packet_size: MAXIMUM_PACKET_SIZE,
                context,
            })
            .await?;

        let packet = self.session.recv().await?;

        if let Ok(connect::ChannelOpenFailure {
            recipient_channel,
            reason,
            description,
            ..
        }) = packet.to()
        {
            if recipient_channel == local_id {
                Ok(ChannelOpen::Rejected {
                    reason,
                    message: description.into_string(),
                })
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else if let Ok(connect::ChannelOpenConfirmation {
            sender_channel: remote_id,
            recipient_channel,
            initial_window_size,
            maximum_packet_size,
        }) = packet.to()
        {
            if recipient_channel == local_id {
                let remote_window_size = Arc::new(AtomicU32::new(initial_window_size));

                let (channel, sender) = Channel::new(
                    remote_id,
                    INITIAL_WINDOW_SIZE,
                    remote_window_size.clone(),
                    maximum_packet_size,
                    self.sender.clone(),
                );

                self.channels.insert(
                    local_id,
                    ChannelDef {
                        sender,
                        remote_window_size,
                    },
                );

                Ok(ChannelOpen::Accepted(channel))
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
        hook: impl channel::Hook,
    ) -> Connect<'s, IO, S, G, impl channel::Hook> {
        let Self {
            session,
            channels,

            sender,
            receiver,

            on_channel_open: _,
            on_global_request,
        } = self;

        Connect {
            session,
            channels,

            sender,
            receiver,

            on_channel_open: hook,
            on_global_request,
        }
    }

    /// Spin up the connect protocol handling, with the registered hooks
    /// to fuel channel I/O and hooks with messages.
    pub async fn spin(mut self) -> Result<Infallible> {
        loop {
            futures::select! {
                msg = self.receiver.recv_async() => {
                    #[allow(clippy::unwrap_used)]
                    let msg = msg.unwrap(); // Will never be disconnected, since this struct always hold a sender.

                    self.session.send(&msg).await?;
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

        if let Ok(connect::GlobalRequest {
            want_reply,
            context,
        }) = packet.to()
        {
            let with_port = matches!(context, connect::GlobalRequestContext::TcpipForward { bind_port, .. } if bind_port == 0);
            let outcome = self.on_global_request.on_request(context);

            if *want_reply {
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
        } else if let Ok(connect::ChannelOpen {
            sender_channel: remote_id,
            initial_window_size,
            maximum_packet_size,
            context,
        }) = packet.to()
        {
            tracing::debug!("Peer requested to open channel %{remote_id}: {context:?}");

            let local_id = self
                .channels
                .keys()
                .max()
                .map(|x| x + 1)
                .unwrap_or_default();
            let remote_window_size = Arc::new(AtomicU32::new(initial_window_size));

            let (channel, sender) = Channel::new(
                remote_id,
                INITIAL_WINDOW_SIZE,
                remote_window_size.clone(),
                maximum_packet_size,
                self.sender.clone(),
            );

            match self.on_channel_open.on_request(context, channel) {
                channel::Outcome::Accept => {
                    self.channels.insert(
                        local_id,
                        ChannelDef {
                            sender,
                            remote_window_size,
                        },
                    );

                    self.session
                        .send(&connect::ChannelOpenConfirmation {
                            recipient_channel: remote_id,
                            sender_channel: local_id,
                            initial_window_size: INITIAL_WINDOW_SIZE,
                            maximum_packet_size: MAXIMUM_PACKET_SIZE,
                        })
                        .await?;

                    tracing::debug!("Channel opened as #{local_id}:%{remote_id}");
                }
                channel::Outcome::Reject {
                    reason,
                    description,
                } => {
                    self.session
                        .send(&connect::ChannelOpenFailure {
                            recipient_channel: remote_id,
                            reason,
                            description,
                            language: Default::default(),
                        })
                        .await?;

                    tracing::debug!("Channel open refused for %{remote_id}");
                }
            }
        } else if let Ok(connect::ChannelClose { recipient_channel }) = packet.to() {
            tracing::debug!("Peer closed channel #{recipient_channel}");

            self.channels.remove(&recipient_channel);
        } else if let Ok(connect::ChannelWindowAdjust {
            recipient_channel,
            bytes_to_add,
        }) = packet.to()
        {
            if let Some(channel) = self.channels.get(&recipient_channel) {
                tracing::debug!("Peer added {bytes_to_add} to window for #{recipient_channel}");

                channel
                    .remote_window_size
                    .fetch_add(bytes_to_add, Ordering::AcqRel);
            } else {
                tracing::warn!("Received a message for closed channel #{recipient_channel}");
            }
        } else if let Ok(msg) = packet.to::<Msg>() {
            if let Some(channel) = self.channels.get(msg.recipient_channel()) {
                if let Err(err) = channel.sender.send_async(msg).await {
                    // If we failed to send the message to the channel,
                    // the receiver has been dropped, so treat it as such and report it as closed.
                    self.channels.remove(err.into_inner().recipient_channel());
                }
            } else {
                tracing::warn!(
                    "Received a message for closed channel #{}",
                    msg.recipient_channel()
                );
            }
        } else {
            tracing::warn!(
                "Received an unhandled packet from peer of length `{}` bytes",
                packet.payload.len()
            );
        }

        Ok(())
    }
}
