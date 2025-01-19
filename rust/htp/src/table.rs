use crate::bstr::Bstr;
use std::{cmp::Ordering, iter::Iterator, ops::Index, slice::SliceIndex};

/// The table structure for key value pairs.
#[derive(Clone, Debug)]
pub struct Table<T> {
    /// Entries in the table.
    pub elements: Vec<(Bstr, T)>,
}

impl<T> Index<usize> for Table<T> {
    type Output = (Bstr, T);
    fn index(&self, idx: usize) -> &(Bstr, T) {
        &self.elements[idx]
    }
}

impl<'a, T> IntoIterator for &'a Table<T> {
    type Item = &'a (Bstr, T);
    type IntoIter = std::slice::Iter<'a, (Bstr, T)>;

    fn into_iter(self) -> std::slice::Iter<'a, (Bstr, T)> {
        self.elements.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Table<T> {
    type Item = &'a mut (Bstr, T);
    type IntoIter = std::slice::IterMut<'a, (Bstr, T)>;

    fn into_iter(self) -> std::slice::IterMut<'a, (Bstr, T)> {
        self.elements.iter_mut()
    }
}

impl<T> IntoIterator for Table<T> {
    type Item = (Bstr, T);
    type IntoIter = std::vec::IntoIter<(Bstr, T)>;

    fn into_iter(self) -> std::vec::IntoIter<(Bstr, T)> {
        self.elements.into_iter()
    }
}

impl<T> Table<T> {
    /// Make a new owned Table with given capacity
    pub fn with_capacity(size: usize) -> Self {
        Self {
            elements: Vec::with_capacity(size),
        }
    }

    /// Add a new tuple (key, item) to the table
    pub fn add(&mut self, key: Bstr, item: T) {
        self.elements.push((key, item));
    }

    /// Retrieve an element from a specific index.
    pub fn get<I>(&self, index: I) -> Option<&I::Output>
    where
        I: SliceIndex<[(Bstr, T)]>,
    {
        self.elements.get(index)
    }

    /// Retrieve a mutable reference to an element from a specific index.
    pub fn get_mut<I>(&mut self, index: I) -> Option<&mut I::Output>
    where
        I: SliceIndex<[(Bstr, T)]>,
    {
        self.elements.get_mut(index)
    }

    /// Search the table for the first tuple with a key matching the given slice, ingnoring ascii case in self
    ///
    /// Returns None if no match is found.
    pub fn get_nocase<K: AsRef<[u8]>>(&self, key: K) -> Option<&(Bstr, T)> {
        self.elements
            .iter()
            .find(|x| x.0.cmp_nocase_trimmed(key.as_ref()) == Ordering::Equal)
    }

    /// Returns the number of elements in the table
    pub fn size(&self) -> usize {
        self.elements.len()
    }
}

// Tests

#[test]
fn Add() {
    let mut t = Table::with_capacity(1);
    let mut k = Bstr::from("Key");
    assert_eq!(0, t.size());
    t.add(k, "Value1");
    assert_eq!(1, t.size());
    k = Bstr::from("AnotherKey");
    t.add(k, "Value2");
    assert_eq!(2, t.size());
}

#[test]
fn GetNoCase() {
    let mut t = Table::with_capacity(2);
    let mut k = Bstr::from("Key1");
    t.add(k, "Value1");
    k = Bstr::from("KeY2");
    t.add(k, "Value2");

    let mut result = t.get_nocase("KEY1");
    let mut res = result.unwrap();
    assert_eq!(Ordering::Equal, res.0.cmp_slice("Key1"));
    assert_eq!("Value1", res.1);

    result = t.get_nocase("keY1");
    res = result.unwrap();
    assert_eq!(Ordering::Equal, res.0.cmp_slice("Key1"));
    assert_eq!("Value1", res.1);

    result = t.get_nocase("key2");
    res = result.unwrap();
    assert_eq!(Ordering::Equal, res.0.cmp_slice("KeY2"));
    assert_eq!("Value2", res.1);

    result = t.get_nocase("NotAKey");
    assert!(result.is_none());
}

#[test]
fn IndexAccess() {
    let mut t = Table::with_capacity(2);
    let mut k = Bstr::from("Key1");
    t.add(k, "Value1");
    k = Bstr::from("KeY2");
    t.add(k, "Value2");

    let res = &t[1];
    assert_eq!(Ordering::Equal, res.0.cmp_slice("KeY2"));
    assert_eq!("Value2", res.1);
    assert_eq!("Value2", t.get(1).unwrap().1);

    let res_mut = t.get_mut(1).unwrap();
    res_mut.1 = "Value3";
    assert_eq!("Value3", t.get(1).unwrap().1);
}

#[test]
fn Iterators() {
    let mut table = Table::with_capacity(2);
    table.add("1".into(), "abc".to_string());
    table.add("2".into(), "def".to_string());

    let mut iter_ref: std::slice::Iter<(Bstr, String)> = (&table).into_iter();
    let (key1, _): &(Bstr, String) = iter_ref.next().unwrap();
    assert_eq!(key1, &"1");
    assert_eq!(table.get_nocase("1").unwrap().1, "abc");

    let mut iter_mut_ref: std::slice::IterMut<(Bstr, String)> = (&mut table).into_iter();
    let (key1, ref mut val1): &mut (Bstr, String) = iter_mut_ref.next().unwrap();
    *val1 = "xyz".to_string();
    assert_eq!(key1, &"1");
    assert_eq!(table.get_nocase("1").unwrap().1, "xyz");

    let mut iter_owned: std::vec::IntoIter<(Bstr, String)> = table.into_iter();
    let (key1, val1) = iter_owned.next().unwrap();
    assert_eq!(key1, "1");
    assert_eq!(val1, "xyz");
}

#[test]
fn Table_Misc() {
    let mut t: Table<&str> = Table::with_capacity(2);

    let mut pkey = Bstr::with_capacity(1);
    pkey.add("p");

    let mut qkey = Bstr::with_capacity(1);
    qkey.add("q");

    t.add(pkey, "1");
    t.add(qkey, "2");

    assert!(t.get_nocase("z").is_none());
    assert_eq!("1", t.get_nocase("p").unwrap().1);
}
