use ssh_packet::{Packet, binrw::meta::ReadMagic, connect};

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
    fn recipient_channel_for(packet: &Packet) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&packet[1..5]);

        u32::from_le_bytes(bytes)
    }

    pub fn parse(packet: &Packet) -> Option<Self> {
        if packet[0] == connect::GlobalRequest::MAGIC {
            Some(Self::GlobalRequest)
        } else if packet[0] == connect::RequestSuccess::MAGIC
            || packet[0] == connect::ForwardingSuccess::MAGIC
            || packet[0] == connect::RequestFailure::MAGIC
        {
            Some(Self::GlobalResponse)
        } else if packet[0] == connect::ChannelOpen::MAGIC {
            Some(Self::ChannelOpenRequest)
        } else if packet[0] == connect::ChannelOpenConfirmation::MAGIC
            || packet[0] == connect::ChannelOpenFailure::MAGIC
        {
            Some(Self::ChannelOpenResponse(Self::recipient_channel_for(
                packet,
            )))
        } else if packet[0] == connect::ChannelWindowAdjust::MAGIC {
            Some(Self::ChannelWindowAdjust(Self::recipient_channel_for(
                packet,
            )))
        } else if packet[0] == connect::ChannelData::MAGIC
            || packet[0] == connect::ChannelExtendedData::MAGIC
        {
            Some(Self::ChannelData(Self::recipient_channel_for(packet)))
        } else if packet[0] == connect::ChannelEof::MAGIC {
            Some(Self::ChannelEof(Self::recipient_channel_for(packet)))
        } else if packet[0] == connect::ChannelClose::MAGIC {
            Some(Self::ChannelClose(Self::recipient_channel_for(packet)))
        } else if packet[0] == connect::ChannelRequest::MAGIC {
            Some(Self::ChannelRequest(Self::recipient_channel_for(packet)))
        } else if packet[0] == connect::ChannelSuccess::MAGIC
            || packet[0] == connect::ChannelFailure::MAGIC
        {
            Some(Self::ChannelResponse(Self::recipient_channel_for(packet)))
        } else {
            None
        }
    }
}
