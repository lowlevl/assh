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

use crate::{channel, global_request, Error, Result, INITIAL_WINDOW_SIZE, MAXIMUM_PACKET_SIZE};

struct ChannelDef {
    sender: flume::Sender<channel::Msg>,
    remote_window_size: Arc<AtomicU32>,
}

/// A wrapper around a [`Session`] to interract with the connect layer.
pub struct Connect<'s, IO, S, G = (), C = ()> {
    session: &'s mut Session<IO, S>,
    channels: HashMap<u32, ChannelDef>,

    on_global_request: G,
    on_channel_open: C,

    sender: flume::Sender<channel::Msg>,
    receiver: flume::Receiver<channel::Msg>,
}

impl<'s, IO, S> Connect<'s, IO, S> {
    /// Create a wrapper around the `session` to handle the connect layer.
    pub(super) fn new(session: &'s mut Session<IO, S>) -> Self {
        let (sender, receiver) = flume::unbounded();

        Self {
            session,
            channels: Default::default(),

            on_global_request: (),
            on_channel_open: (),

            sender,
            receiver,
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
    pub async fn global_request(&mut self, context: connect::GlobalRequestContext) -> Result<()> {
        todo!()
    }

    /// Register the handler for _global requests_.
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

            on_channel_open: on_channel,
            on_global_request: _,

            sender,
            receiver,
        } = self;

        Connect {
            session,
            channels,

            on_channel_open: on_channel,
            on_global_request: hook,

            sender,
            receiver,
        }
    }

    /// Request a new _channel_ with the provided `context`.
    pub async fn channel(
        &mut self,
        context: connect::ChannelOpenContext,
    ) -> Result<channel::Channel> {
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

        if let Ok(connect::ChannelOpenConfirmation {
            sender_channel: remote_id,
            recipient_channel,
            initial_window_size,
            maximum_packet_size,
        }) = packet.to()
        {
            if recipient_channel == local_id {
                let remote_window_size = Arc::new(AtomicU32::new(initial_window_size));

                let (channel, sender) = channel::Channel::new(
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

                Ok(channel)
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else if let Ok(connect::ChannelOpenFailure {
            recipient_channel,
            reason,
            description,
            ..
        }) = packet.to()
        {
            if recipient_channel == local_id {
                Err(Error::ChannelOpenFailure {
                    reason,
                    message: description.into_string(),
                })
            } else {
                Err(assh::Error::UnexpectedMessage.into())
            }
        } else {
            Err(assh::Error::UnexpectedMessage.into())
        }
    }

    /// Register the handler for _channel open requests_.
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

            on_channel_open: _,
            on_global_request,

            sender,
            receiver,
        } = self;

        Connect {
            session,
            channels,

            on_channel_open: hook,
            on_global_request,

            sender,
            receiver,
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

        if let Ok(connect::GlobalRequest { .. }) = packet.to() {
            // TODO: Implement global-requests.
            todo!()
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

            let (channel, sender) = channel::Channel::new(
                remote_id,
                INITIAL_WINDOW_SIZE,
                remote_window_size.clone(),
                maximum_packet_size,
                self.sender.clone(),
            );

            match self.on_channel_open.process(context, channel) {
                channel::Response::Accept => {
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
                channel::Response::Reject {
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
        } else if let Ok(msg) = packet.to::<channel::Msg>() {
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
