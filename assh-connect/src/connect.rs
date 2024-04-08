use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use assh::{
    layer::Layer,
    session::{Session, Side},
};
use futures::{AsyncBufRead, AsyncWrite, FutureExt};
use ssh_packet::connect;

use crate::{channel, Error, Result, INITIAL_WINDOW_SIZE, MAXIMUM_PACKET_SIZE};

struct ChannelDef {
    sender: flume::Sender<channel::Msg>,
    peer_window_size: Arc<AtomicU32>,
}

/// A wrapper around [`assh::session::Session`] to handle the connect layer.
pub struct Connect<I, S, L> {
    session: Session<I, S, L>,
    channels: HashMap<u32, ChannelDef>,

    sender: flume::Sender<channel::Msg>,
    receiver: flume::Receiver<channel::Msg>,
}

impl<I: AsyncBufRead + AsyncWrite + Unpin + Send, S: Side, L: Layer<S>> Connect<I, S, L> {
    /// Create a wrapper around the `session` to handle the connect layer.
    pub fn new(session: Session<I, S, L>) -> Self {
        let (sender, receiver) = flume::unbounded();

        Self {
            session,
            channels: Default::default(),

            sender,
            receiver,
        }
    }

    /// Ask the peer to open a [`channel::Channel`] from the provided `context`.
    pub async fn channel(
        &mut self,
        context: connect::ChannelOpenContext,
    ) -> Result<channel::Channel> {
        let identifier = self
            .channels
            .keys()
            .max()
            .map(|x| x + 1)
            .unwrap_or_default();

        self.session
            .send(&connect::ChannelOpen {
                sender_channel: identifier,
                initial_window_size: INITIAL_WINDOW_SIZE,
                maximum_packet_size: MAXIMUM_PACKET_SIZE,
                context,
            })
            .await?;

        let packet = self.session.recv().await?;

        if let Ok(connect::ChannelOpenConfirmation {
            sender_channel,
            recipient_channel,
            initial_window_size,
            maximum_packet_size,
        }) = packet.to()
        {
            if recipient_channel == identifier {
                let peer_window_size = Arc::new(AtomicU32::new(initial_window_size));

                let (channel, sender) = channel::Channel::new(
                    sender_channel,
                    INITIAL_WINDOW_SIZE,
                    peer_window_size.clone(),
                    maximum_packet_size,
                    self.sender.clone(),
                );

                self.channels.insert(
                    identifier,
                    ChannelDef {
                        sender,
                        peer_window_size,
                    },
                );

                Ok(channel)
            } else {
                Err(Error::UnexpectedMessage)
            }
        } else if let Ok(connect::ChannelOpenFailure {
            recipient_channel,
            reason,
            description,
            ..
        }) = packet.to()
        {
            if recipient_channel == identifier {
                Err(Error::ChannelOpenFailure {
                    reason,
                    message: description.into_string(),
                })
            } else {
                Err(Error::UnexpectedMessage)
            }
        } else {
            Err(Error::UnexpectedMessage)
        }
    }

    /// Process incoming messages endlessly.
    pub async fn run(
        mut self,
        channel_handler: impl Fn(connect::ChannelOpenContext, channel::Channel) -> bool,
    ) -> Result<Infallible> {
        loop {
            futures::select! {
                msg = self.receiver.recv_async() => {
                    #[allow(clippy::unwrap_used)]
                    let msg = msg.unwrap(); // Will never be disconnected, since this struct always hold a sender.

                    self.session.send(&msg).await?;
                }
                res = self.session.readable().fuse() => {
                    res?;

                    self.rx(&channel_handler).await?;
                }
            }
        }
    }

    async fn rx(
        &mut self,
        channel_handler: &impl Fn(connect::ChannelOpenContext, channel::Channel) -> bool,
    ) -> Result<()> {
        let packet = self.session.recv().await?;

        if let Ok(connect::GlobalRequest { .. }) = packet.to() {
            unimplemented!()
        } else if let Ok(connect::ChannelOpen {
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            context,
        }) = packet.to()
        {
            tracing::debug!("Peer requested to open channel %{sender_channel}: {context:?}");

            let identifier = self
                .channels
                .keys()
                .max()
                .map(|x| x + 1)
                .unwrap_or_default();
            let peer_window_size = Arc::new(AtomicU32::new(initial_window_size));

            let (channel, sender) = channel::Channel::new(
                sender_channel,
                INITIAL_WINDOW_SIZE,
                peer_window_size.clone(),
                maximum_packet_size,
                self.sender.clone(),
            );

            if channel_handler(context, channel) {
                self.channels.insert(
                    identifier,
                    ChannelDef {
                        sender,
                        peer_window_size,
                    },
                );

                self.session
                    .send(&connect::ChannelOpenConfirmation {
                        recipient_channel: sender_channel,
                        sender_channel: identifier,
                        initial_window_size: INITIAL_WINDOW_SIZE,
                        maximum_packet_size: MAXIMUM_PACKET_SIZE,
                    })
                    .await?;

                tracing::debug!("Channel opened as #{identifier}:%{sender_channel}");
            } else {
                self.session
                    .send(&connect::ChannelOpenFailure {
                        recipient_channel: sender_channel,
                        reason: todo!(),
                        description: todo!(),
                        language: todo!(),
                    })
                    .await?;

                tracing::debug!("Channel open refused for %{sender_channel}");
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
                    .peer_window_size
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
