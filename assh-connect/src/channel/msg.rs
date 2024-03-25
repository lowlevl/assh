use binrw::binrw;
use ssh_packet::connect;

/// The purpose of this macro is to automatically document variants
/// and link to the underlying item documentation.
macro_rules! message {
    ($( $name:ident($path:path) ),+ $(,)?) => {
        /// A channel message.
        ///
        #[binrw]
        #[derive(Debug, Clone)]
        #[brw(big)]
        pub enum Msg {
            $(
                #[doc = concat!("See [`", stringify!($path), "`] for more details.")]
                $name($path)
            ),+
        }
    };
}

message! {
    ChannelWindowAdjust(connect::ChannelWindowAdjust),
    ChannelData(connect::ChannelData),
    ChannelExtendedData(connect::ChannelExtendedData),
    ChannelEof(connect::ChannelEof),
    ChannelClose(connect::ChannelClose),
    ChannelRequest(connect::ChannelRequest),
    ChannelSuccess(connect::ChannelSuccess),
    ChannelFailure(connect::ChannelFailure),
}
