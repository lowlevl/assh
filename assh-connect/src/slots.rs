use std::sync::{Arc, RwLock, Weak};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lease<T> {
    index: usize,
    pointer: Arc<Option<T>>,
}

impl<T> Lease<T> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn value(&self) -> &T {
        (*self.pointer)
            .as_ref()
            .expect("This `Lease` was malformed")
    }
}

pub struct Reserved<'s, T, const N: usize> {
    slots: &'s Slots<T, N>,
    index: usize,
    _reservation: Arc<Option<T>>,
}

impl<'s, T, const N: usize> Reserved<'s, T, N> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn into_lease(self, value: T) -> Lease<T> {
        let pointer = Arc::new(Some(value));

        let index = self.index;

        let mut slots = self
            .slots
            .inner
            .write()
            .expect("This `Slots`'s lock has been poisonned");
        let slot = slots
            .get_mut(index)
            .expect("Lease is invalid for the `Slots` instance");

        *slot = Arc::downgrade(&pointer);

        Lease { index, pointer }
    }
}

#[derive(Debug)]
pub struct Slots<T, const N: usize> {
    inner: RwLock<[Weak<Option<T>>; N]>,
}

impl<T, const N: usize> Default for Slots<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Slots<T, N> {
    pub fn new() -> Self {
        Self {
            inner: std::array::from_fn(|_| Default::default()).into(),
        }
    }

    pub fn reserve(&self) -> Option<Reserved<'_, T, N>> {
        self.inner
            .write()
            .expect("This `Slots`'s lock has been poisonned")
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.strong_count() == 0)
            .map(|(index, slot)| {
                let pointer = Arc::new(None);

                *slot = Arc::downgrade(&pointer);

                Reserved {
                    slots: self,
                    index,
                    _reservation: pointer,
                }
            })
    }

    pub fn insert(&self, value: T) -> Option<Lease<T>> {
        self.reserve().map(|reserved| reserved.into_lease(value))
    }

    pub fn get(&self, index: usize) -> Option<Lease<T>> {
        self.inner
            .read()
            .expect("This `Slots`'s lock has been poisonned")
            .get(index)
            .and_then(Weak::upgrade)
            .map(|pointer| Lease { index, pointer })
    }
}
