use ssh_packet::{binrw, connect};

/// The purpose of this macro is to automatically document variants
/// and link to the underlying item documentation.
macro_rules! message {
    ($(#[$($attrss:tt)*])* $struct:ident;
        $( $name:ident($path:path) ),+ $(,)?)
        => {
        #[binrw::binrw]
        #[derive(Debug, Clone)]
        #[brw(big)]
        $(#[$($attrss)*])*
        pub enum $struct {
            $(
                #[doc = concat!("See [`", stringify!($path), "`] for more details.")]
                $name($path)
            ),+
        }
    };
}

message! {
    /// A channel message.
    Msg;

    WindowAdjust(connect::ChannelWindowAdjust),
    Data(connect::ChannelData),
    ExtendedData(connect::ChannelExtendedData),
    Eof(connect::ChannelEof),
    Request(connect::ChannelRequest),
    Success(connect::ChannelSuccess),
    Failure(connect::ChannelFailure),
}

impl Msg {
    pub fn recipient_channel(&self) -> &u32 {
        let (Self::WindowAdjust(connect::ChannelWindowAdjust {
            recipient_channel, ..
        })
        | Self::Data(connect::ChannelData {
            recipient_channel, ..
        })
        | Self::ExtendedData(connect::ChannelExtendedData {
            recipient_channel, ..
        })
        | Self::Eof(connect::ChannelEof {
            recipient_channel, ..
        })
        | Self::Request(connect::ChannelRequest {
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
