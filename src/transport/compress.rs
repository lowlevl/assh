use strum::{EnumString, EnumVariantNames};

#[derive(Debug, Default)]
pub struct CompressPair {
    pub rx: CompressAlg,
    pub tx: CompressAlg,
}

#[derive(Debug, Default, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum CompressAlg {
    /// Zlib compression.
    Zlib,

    /// Zlib compression (extension name).
    #[strum(serialize = "zlib@openssh.com")]
    ZlibExt,

    /// No compression.
    #[default]
    None,
}
