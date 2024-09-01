use crate::mux::slots::Lease;

#[derive(Debug, Clone)]
pub struct Id(Lease<u32>);

impl Id {
    pub fn local(&self) -> u32 {
        self.0.index() as u32
    }

    pub fn remote(&self) -> u32 {
        *self.0.value()
    }
}

impl From<Lease<u32>> for Id {
    fn from(value: Lease<u32>) -> Self {
        Self(value)
    }
}
