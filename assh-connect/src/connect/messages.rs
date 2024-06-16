use std::num::NonZeroU32;

use ssh_packet::{binrw, connect};

#[binrw::binrw]
#[brw(big)]
#[derive(Debug)]
pub enum Control {
    Request(connect::ChannelRequest),
    Success(connect::ChannelSuccess),
    Failure(connect::ChannelFailure),
}

impl Control {
    pub fn recipient_channel(&self) -> &u32 {
        let (Self::Request(connect::ChannelRequest {
            recipient_channel, ..
        })
        | Self::Success(connect::ChannelSuccess {
            recipient_channel, ..
        })
        | Self::Failure(connect::ChannelFailure {
            recipient_channel, ..
        })) = self;

        recipient_channel
    }
}

#[binrw::binrw]
#[brw(big)]
#[derive(Debug)]
pub enum Data {
    Data(connect::ChannelData),
    ExtendedData(connect::ChannelExtendedData),
}

impl Data {
    pub fn recipient_channel(&self) -> &u32 {
        let (Self::Data(connect::ChannelData {
            recipient_channel, ..
        })
        | Self::ExtendedData(connect::ChannelExtendedData {
            recipient_channel, ..
        })) = self;

        recipient_channel
    }

    pub fn data_type(&self) -> Option<NonZeroU32> {
        match self {
            Self::Data(_) => None,
            Self::ExtendedData(connect::ChannelExtendedData { data_type, .. }) => Some(*data_type),
        }
    }

    pub fn data(self) -> Vec<u8> {
        let (Self::Data(connect::ChannelData { data, .. })
        | Self::ExtendedData(connect::ChannelExtendedData { data, .. })) = self;

        data.into_vec()
    }
}
