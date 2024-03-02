use bitflags::bitflags;

/// Set of available connection methods to the layer.
#[derive(Debug)]
pub struct Methods(u8);

bitflags! {
   impl Methods: u8 {
        /// The SSH `none` authentication method.
        const NONE = 1 << 0;

        /// The SSH `publickey` authentication method.
        const PUBLICKEY = 1 << 1;

        /// The SSH `password` authentication method.
        const PASSWORD = 1 << 2;

        /// The SSH `hostbased` authentication method.
        const HOSTBASED = 1 << 3;

        /// The SSH `keyboard-interactive` authentication method.
        const KEYBOARD_INTERACTIVE = 1 << 4;
    }
}

impl Default for Methods {
    fn default() -> Self {
        Self::NONE
    }
}
