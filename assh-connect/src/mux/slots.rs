use std::sync::{Arc, RwLock, Weak};

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

    pub fn reserve(&self) -> Option<Reservation<'_, T, N>> {
        self.inner
            .write()
            .expect("This `Slots`'s lock has been poisonned")
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.strong_count() == 0)
            .map(|(index, slot)| {
                let pointer = Arc::new(None);

                *slot = Arc::downgrade(&pointer);

                Reservation {
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

pub struct Reservation<'s, T, const N: usize> {
    slots: &'s Slots<T, N>,
    index: usize,
    _reservation: Arc<Option<T>>,
}

impl<'s, T, const N: usize> Reservation<'s, T, N> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_reserves_and_releases() {
        let slots = Slots::<(), 4>::new();

        let one = slots.reserve();
        let two = slots.reserve();
        let three = slots.reserve();
        let four = slots.reserve();
        let five = slots.reserve();

        assert!(one.is_some());
        assert!(two.is_some());
        assert!(three.is_some());
        assert!(four.is_some());
        assert!(five.is_none());

        drop(three);

        let six = slots
            .reserve()
            .expect("Unable to get a reservation on the `Slots` instance");

        assert!(six.index() == 2);
    }

    #[test]
    fn it_leases_and_releases() {
        let slots = Slots::<(), 4>::new();

        let one = slots.insert(());
        let two = slots.insert(());
        let three = slots.insert(());
        let four = slots.insert(());
        let five = slots.insert(());

        assert!(one.is_some());
        assert!(two.is_some());
        assert!(three.is_some());
        assert!(four.is_some());
        assert!(five.is_none());

        drop(three);

        let six = slots
            .insert(())
            .expect("Unable to get a lease on the `Slots` instance");

        assert!(six.index() == 2);
    }

    #[test]
    fn it_mixes_leases_and_reservations() {
        let slots = Slots::<(), 4>::new();

        let one = slots.insert(());
        let two = slots.reserve();
        let three = slots.reserve();
        let four = slots.reserve();
        let five = slots.insert(());

        assert!(one.is_some());
        assert!(two.is_some());
        assert!(three.is_some());
        assert!(four.is_some());
        assert!(five.is_none());

        drop(three);

        let six = slots
            .insert(())
            .expect("Unable to get a lease on the `Slots` instance");

        assert!(six.index() == 2);
    }

    #[test]
    fn lease_and_get_matches() {
        let slots = Slots::<usize, 2>::new();

        let lease = slots
            .insert(1234567)
            .expect("Unable to get a lease on the `Slots` instance");

        assert_eq!(
            slots
                .get(lease.index())
                .expect("Couldn't find Lease that exists")
                .value(),
            lease.value()
        )
    }

    #[test]
    fn out_of_bound_lease() {
        let slots = Slots::<(), 4>::new();

        let _one = slots.insert(());
        let _two = slots.reserve();
        let _three = slots.reserve();

        assert!(slots.get(usize::MAX).is_none());
    }
}
