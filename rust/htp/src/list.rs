//! A continuously growing list
//!
//! This container implements a list that can only grow as elements are added and removed.
//! This is implemented as a Vec<Option<T>> where each element is either present as a Some()
//! or is not present as a None. New elements are always pushed to the end of the list and the
//! capacity grows to accommodate and removed elements are substituted with a `None`; removal or
//! replace operations will never cause another element to move indices. This is done to
//! ensure that indexes are always valid even after other operations are executed on the list.

use crate::HtpStatus;
use core::{ops::Index, slice::SliceIndex};

/// The List structure
#[derive(Clone, Debug)]
pub struct List<T> {
    elements: Vec<Option<T>>,
}

/// Facilitates creating iterators over `List`
pub struct IntoIter<'a, T> {
    inner: std::slice::Iter<'a, Option<T>>,
}

impl<'a, T> Iterator for IntoIter<'a, T> {
    type Item = &'a T;

    /// Returns a reference to the next element.
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(next) = self.inner.next() {
            if let Some(next) = next {
                return Some(next);
            }
        }
        None
    }
}

impl<'a, T> IntoIterator for &'a List<T> {
    type Item = &'a T;
    type IntoIter = IntoIter<'a, T>;

    /// Returns an iterator over the List
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.elements.iter(),
        }
    }
}

impl<T, I: SliceIndex<[Option<T>]>> Index<I> for List<T> {
    type Output = I::Output;

    #[inline]
    /// This allows for square bracket indexing of List.
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.elements, index)
    }
}

impl<T> Default for List<T> {
    fn default() -> List<T> {
        Self {
            elements: Vec::with_capacity(32),
        }
    }
}

impl<T> List<T> {
    /// Create a new list with specified capacity.
    pub fn with_capacity(size: usize) -> Self {
        Self {
            elements: Vec::with_capacity(size),
        }
    }

    /// Return the current capacity of the List.
    pub fn capacity(&self) -> usize {
        self.elements.capacity()
    }

    /// Remove all elements from the list.
    pub fn clear(&mut self) {
        self.elements.clear();
    }

    /// Find the element at the given index.
    ///
    /// If the index is out of bounds it returns `None`, otherwise it will return the value
    /// at the given index.  The value at the given index can also be `None` if it has
    /// been removed.
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.elements.get(idx).map(|val| val.as_ref()).flatten()
    }

    /// Find the element at the given index.
    ///
    /// Functions much like [`get`](crate::list::List::get) but returns a mutable reference.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut T> {
        self.elements.get_mut(idx).map(|val| val.as_mut()).flatten()
    }

    /// Retrieve the last element in the list.
    ///
    /// The element returned will always be the last element. The returned element can be
    /// `None` if the element as been removed.
    pub fn get_last(&self) -> Option<&T> {
        self.elements.last().map(|val| val.as_ref()).flatten()
    }

    /// Retrieve a mutable reference to the last element in the list.
    ///
    /// Functions much like [`get_last`](crate::list::List::get_last) but returns a
    /// mutable reference.
    pub fn get_last_mut(&mut self) -> Option<&mut T> {
        let idx = self.elements.len() - 1; //Works around borrowing twice as mut/immut
        self.elements.get_mut(idx).map(|val| val.as_mut()).flatten()
    }

    /// Remove one element from the end of the list.
    ///
    /// Returns the last element which is also removed, or None if the list is empty.
    /// Unlike `remove` this function shrinks the size of the list instead of replacing
    /// the element with `None`.
    pub fn pop(&mut self) -> Option<T> {
        self.elements.pop().flatten()
    }

    /// Add new element to the end of the list.
    ///
    /// This function may expand the capacity of the list when necessary.
    pub fn push(&mut self, value: T) {
        self.elements.push(Some(value));
    }

    /// Replace the element at the given index with the provided element.
    ///
    /// When the index is within range it will do the replacement, even on previously
    /// removed elements.  If the index is out of bounds it will return `HtpStatus::DECLINED`.
    pub fn replace(&mut self, idx: usize, value: T) -> Result<(), HtpStatus> {
        if idx < self.elements.len() {
            self.elements[idx] = Some(value);
            Ok(())
        } else {
            Err(HtpStatus::DECLINED)
        }
    }

    /// Remove the element at the given index.
    ///
    /// Returns HtpStatus::DECLINED if no element at the given index exists.
    /// This does not resize the list nor affect ordering, so
    /// [`len`](crate::list::List::len) and [`get`](crate::list::List::get) (on any other
    /// index) will behave identically before and after a removal.
    pub fn remove(&mut self, idx: usize) -> Result<(), HtpStatus> {
        if idx < self.elements.len() {
            self.elements[idx] = None;
            Ok(())
        } else {
            Err(HtpStatus::DECLINED)
        }
    }

    /// Returns the size of the list.
    ///
    /// Returns the effective size of the list including `None` values where they have been
    /// removed.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::{list::List, HtpStatus};

    #[test]
    fn create() {
        let list: List<usize> = List::with_capacity(4);
        assert_eq!(list.capacity(), 4);
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn insert() {
        let mut list = List::with_capacity(4);
        list.push('a');
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0), Some(&'a'));
    }

    #[test]
    fn clear() {
        let mut list = List::with_capacity(4);
        list.push('a');
        assert_eq!(list.len(), 1);
        list.clear();
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn remove() {
        let mut list = List::with_capacity(4);
        list.push('a');
        list.push('b');
        list.push('c');
        assert_eq!(list.len(), 3);
        let status = list.remove(1); // 'b'
        assert_eq!(status, Ok(()));
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0), Some(&'a'));
        assert_eq!(list.get(1), None);
        assert_eq!(list.get(2), Some(&'c'));
    }

    #[test]
    fn get_out_of_bounds() {
        let mut list = List::with_capacity(4);
        assert_eq!(list.get(0), None);
        list.push('a');
        assert_eq!(list.get(0), Some(&'a'));
        assert_eq!(list.get(1), None);
    }

    #[test]
    fn get_last() {
        let mut list = List::with_capacity(4);
        list.push('a');
        assert_eq!(list.len(), 1);
        let elem = list.get_last();
        assert_eq!(list.len(), 1);
        assert_eq!(elem, Some(&'a'));

        let elem = list.get_last_mut().unwrap();
        *elem = 'b';
        assert_eq!(list.get(0), Some(&'b'));
    }

    #[test]
    fn remove_out_of_bounds() {
        let mut list = List::with_capacity(4);
        list.push('a');
        assert_eq!(list.len(), 1);
        let status = list.remove(2);
        assert_eq!(status, Err(HtpStatus::DECLINED));
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0), Some(&'a'));
    }

    #[test]
    fn pop() {
        let mut list = List::with_capacity(4);
        let elem = list.pop();
        assert_eq!(elem, None);
        list.push('a');
        assert_eq!(list.len(), 1);
        let elem = list.pop();
        assert_eq!(elem, Some('a'));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn replace() {
        let mut list = List::with_capacity(4);
        let status = list.replace(0, 'a');
        assert_eq!(status, Err(HtpStatus::DECLINED));
        list.push('a');
        list.push('b');
        assert_eq!(list.replace(0, 'b'), Ok(())); //Replace element
        assert_eq!(list.get(0), Some(&'b'));
        let _ = list.remove(0);
        assert_eq!(list.get(0), None);
        let _ = list.replace(0, 'a'); //Replace deleted element
        assert_eq!(list.get(0), Some(&'a'));
        assert_eq!(list.replace(2, 'a'), Err(HtpStatus::DECLINED)); //Replace out of bounds
    }

    #[test]
    fn iterators() {
        let mut list = List::with_capacity(4);
        list.push('a');
        list.push('b');
        list.push('c');
        let list = list; // No long mut

        let mut list_copy = Vec::new();
        for each in &list {
            list_copy.push(each);
        }
        assert_eq!(list_copy, [&'a', &'b', &'c']);
    }

    #[test]
    fn iterators_with_gaps() {
        let mut list = List::with_capacity(4);
        list.push('a');
        list.push('b');
        list.push('c');
        let _ = list.remove(1);
        let list = list;

        let mut list_copy = Vec::new();
        for each in &list {
            list_copy.push(each);
        }
        assert_eq!(list_copy, [&'a', &'c']);
    }

    #[test]
    fn iterator_empty() {
        let list: List<char> = List::with_capacity(4);
        for each in &list {
            assert!(
                false,
                "list had value when it should have been empty.  Value: {}",
                each
            );
        }
    }

    #[test]
    fn index() {
        let mut list = List::with_capacity(4);
        list.push('a');
        list.push('b');

        assert_eq!(list[0], Some('a'));
        assert_eq!(list[1], Some('b'));
    }

    #[test]
    fn expand1() {
        let mut l = List::with_capacity(2);

        l.push("1");
        l.push("2");

        assert_eq!(2, l.len());

        l.push("3");

        assert_eq!(3, l.len());

        let p = l.get(0).unwrap();
        assert_eq!(*p, "1");

        let p = l.get(1).unwrap();
        assert_eq!(*p, "2");

        let p = l.get(2).unwrap();
        assert_eq!(*p, "3");

        drop(&l);
    }

    #[test]
    fn expand2() {
        let mut l = List::with_capacity(2);
        l.push("1");
        l.push("2");

        assert_eq!(2, l.len());

        l.push("3");
        l.push("4");

        assert_eq!(4, l.len());

        let p = l.get(0).unwrap();
        assert_eq!(*p, "1");

        let p = l.get(1).unwrap();
        assert_eq!(*p, "2");

        let p = l.get(2).unwrap();
        assert_eq!(*p, "3");

        let p = l.pop().unwrap();
        assert_eq!(p, "4");
    }

    #[test]
    fn misc() {
        let mut l = List::with_capacity(16);
        l.push("1");
        l.push("2");
        l.push("3");

        assert_eq!(3, l.len());

        let p = l.pop().unwrap();
        assert_eq!("3", p);

        assert_eq!(2, l.len());

        let p = l.pop().unwrap();
        assert_eq!(p, "2");

        let p = l.pop().unwrap();
        assert_eq!(p, "1");

        let p = l.pop();
        assert!(p.is_none());
    }

    #[test]
    fn misc2() {
        let mut l = List::with_capacity(2);
        l.push("1");
        l.push("2");
        l.push("3");
        let p = l.get(2).unwrap();
        assert_eq!(*p, "3");
        assert_eq!(3, l.len());
        let _ = l.replace(2, "4");
        let p = l.pop().unwrap();
        assert_eq!(p, "4");
    }
}
