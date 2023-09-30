use strum::{EnumString, EnumVariantNames};

#[derive(Debug, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum KexAlg {
    Curve25519Sha256,

    #[strum(serialize = "curve25519-sha256@libssh.org")]
    Curve25519Sha256Ext,

    DiffieHellmanGroup14Sha256,

    DiffieHellmanGroup14Sha1,

    DiffieHellmanGroup1Sha1,
}
