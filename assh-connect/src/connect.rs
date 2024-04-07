use std::{collections::HashMap, convert::Infallible};

use assh::{
    layer::Layer,
    session::{Session, Side},
};
use futures::{AsyncBufRead, AsyncWrite, FutureExt};
use ssh_packet::connect;

use crate::{channel, Error, Result, INITIAL_WINDOW_SIZE, MAXIMUM_PACKET_SIZE};

/// A wrapper around [`assh::session::Session`] to handle the connect layer.
pub struct Connect<I, S, L> {
    session: Session<I, S, L>,
    channels: HashMap<u32, flume::Sender<channel::Msg>>,

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
        let identifier = self.channels.keys().max().unwrap_or(&0) + 1;

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
                let (channel, sender) = channel::Channel::new(
                    sender_channel,
                    INITIAL_WINDOW_SIZE,
                    initial_window_size,
                    maximum_packet_size,
                    self.sender.clone(),
                );

                self.channels.insert(identifier, sender);

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
    pub async fn process(mut self) -> Result<Infallible> {
        loop {
            futures::select! {
                msg = self.receiver.recv_async() => {
                    #[allow(clippy::unwrap_used)]
                    let msg = msg.unwrap(); // Will never be disconnected, since this struct always hold a sender.

                    self.tx(msg).await?;
                }
                res = self.session.readable().fuse() => {
                    res?;

                    self.rx().await?;
                }
            }
        }
    }

    async fn tx(&mut self, msg: channel::Msg) -> Result<()> {
        self.session.send(&msg).await?;

        Ok(())
    }

    async fn rx(&mut self) -> Result<()> {
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
            let identifier = self.channels.keys().max().unwrap_or(&0) + 1;

            let (channel, sender) = channel::Channel::new(
                sender_channel,
                INITIAL_WINDOW_SIZE,
                initial_window_size,
                maximum_packet_size,
                self.sender.clone(),
            );

            let response = true;

            if response {
                self.channels.insert(identifier, sender);

                self.session
                    .send(&connect::ChannelOpenConfirmation {
                        recipient_channel: sender_channel,
                        sender_channel: identifier,
                        initial_window_size: INITIAL_WINDOW_SIZE,
                        maximum_packet_size: MAXIMUM_PACKET_SIZE,
                    })
                    .await?;
            } else {
                self.session
                    .send(&connect::ChannelOpenFailure {
                        recipient_channel: sender_channel,
                        reason: todo!(),
                        description: todo!(),
                        language: todo!(),
                    })
                    .await?;
            }
        } else if let Ok(connect::ChannelClose { recipient_channel }) = packet.to() {
            self.channels.remove(&recipient_channel);
        } else if let Ok(msg) = packet.to::<channel::Msg>() {
            if let Some(sender) = self.channels.get(msg.recipient_channel()) {
                if let Err(err) = sender.send_async(msg).await {
                    // If we failed to send the message to the channel,
                    // the receiver has been dropped, so treat it as such and report it as closed.
                    self.channels.remove(err.into_inner().recipient_channel());
                }
            } else {
                tracing::warn!(
                    "Received a message for a closed channel (#{})",
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
