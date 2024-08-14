use ssh_packet::{connect, Packet};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum Interest {
    GlobalRequest,
    GlobalResponse,

    ChannelOpen,
    ChannelOpenResponse(u32),

    ChannelWindowAdjust(u32),
    ChannelData(u32),
    ChannelEof(u32),
    ChannelClose(u32),

    ChannelRequest(u32),
    ChannelResponse(u32),

    None,
}

impl From<&Packet> for Interest {
    fn from(packet: &Packet) -> Self {
        // TODO: Maybe optimize this caracterization without using `binrw` when it is expensive to (Data mainly).

        if packet.to::<connect::GlobalRequest>().is_ok() {
            Self::GlobalRequest
        } else if packet.to::<connect::RequestSuccess>().is_ok()
            || packet.to::<connect::ForwardingSuccess>().is_ok()
            || packet.to::<connect::RequestFailure>().is_ok()
        {
            Self::GlobalResponse
        } else if packet.to::<connect::ChannelOpen>().is_ok() {
            Self::ChannelOpen
        } else if let Ok(message) = packet.to::<connect::ChannelOpenConfirmation>() {
            Self::ChannelOpenResponse(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelOpenFailure>() {
            Self::ChannelOpenResponse(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelWindowAdjust>() {
            Self::ChannelWindowAdjust(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelData>() {
            Self::ChannelData(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelExtendedData>() {
            Self::ChannelData(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelEof>() {
            Self::ChannelEof(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelClose>() {
            Self::ChannelClose(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelRequest>() {
            Self::ChannelRequest(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelSuccess>() {
            Self::ChannelResponse(message.recipient_channel)
        } else if let Ok(message) = packet.to::<connect::ChannelFailure>() {
            Self::ChannelResponse(message.recipient_channel)
        } else {
            Self::None
        }
    }
}
