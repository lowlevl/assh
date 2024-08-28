use ssh_packet::{connect, Packet};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum Interest {
    GlobalRequest,
    GlobalResponse,

    ChannelOpenRequest,
    ChannelOpenResponse(u32),

    ChannelWindowAdjust(u32),
    ChannelData(u32),
    ChannelEof(u32),
    ChannelClose(u32),

    ChannelRequest(u32),
    ChannelResponse(u32),
}

impl Interest {
    pub fn parse(packet: &Packet) -> Option<Self> {
        // TODO: Maybe optimize this caracterization without using `binrw` when it is expensive to (Data mainly).

        if packet.to::<connect::GlobalRequest>().is_ok() {
            Some(Self::GlobalRequest)
        } else if packet.to::<connect::RequestSuccess>().is_ok()
            || packet.to::<connect::ForwardingSuccess>().is_ok()
            || packet.to::<connect::RequestFailure>().is_ok()
        {
            Some(Self::GlobalResponse)
        } else if packet.to::<connect::ChannelOpen>().is_ok() {
            Some(Self::ChannelOpenRequest)
        } else if let Ok(message) = packet.to::<connect::ChannelOpenConfirmation>() {
            Some(Self::ChannelOpenResponse(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelOpenFailure>() {
            Some(Self::ChannelOpenResponse(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelWindowAdjust>() {
            Some(Self::ChannelWindowAdjust(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelData>() {
            Some(Self::ChannelData(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelExtendedData>() {
            Some(Self::ChannelData(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelEof>() {
            Some(Self::ChannelEof(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelClose>() {
            Some(Self::ChannelClose(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelRequest>() {
            Some(Self::ChannelRequest(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelSuccess>() {
            Some(Self::ChannelResponse(message.recipient_channel))
        } else if let Ok(message) = packet.to::<connect::ChannelFailure>() {
            Some(Self::ChannelResponse(message.recipient_channel))
        } else {
            None
        }
    }
}
