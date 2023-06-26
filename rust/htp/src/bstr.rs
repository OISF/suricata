use bstr::{BString, ByteSlice};
use core::cmp::Ordering;
use std::ops::{Deref, DerefMut};

/// Bstr is a convenience wrapper around binary data that adds string-like functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bstr {
    // Wrap a BString under the hood. We want to be able to
    // implement behaviours on top of this if needed, so we wrap
    // it instead of exposing it directly in our public API.
    s: BString,
}

impl Default for Bstr {
    fn default() -> Self {
        Self {
            s: BString::from(Vec::new()),
        }
    }
}

impl Bstr {
    /// Make a new owned Bstr
    pub fn new() -> Self {
        Bstr {
            s: BString::from(Vec::new()),
        }
    }

    /// Make a new owned Bstr with given capacity
    pub fn with_capacity(len: usize) -> Self {
        Bstr {
            s: BString::from(Vec::with_capacity(len)),
        }
    }

    /// Split the Bstr into a a collection of substrings, seperated by the given byte string.
    /// Each element yielded is guaranteed not to include the splitter substring.
    /// Returns a Vector of the substrings.
    pub fn split_str_collect<'b, B: ?Sized + AsRef<[u8]>>(&'b self, splitter: &'b B) -> Vec<&[u8]> {
        self.s.as_bstr().split_str(splitter.as_ref()).collect()
    }

    /// Compare this bstr with the given slice
    pub fn cmp_slice<B: AsRef<[u8]>>(&self, other: B) -> Ordering {
        self.as_slice().cmp(other.as_ref())
    }

    /// Return true if self is equal to other
    pub fn eq_slice<B: AsRef<[u8]>>(&self, other: B) -> bool {
        self.cmp_slice(other) == Ordering::Equal
    }

    /// Compare bstr with the given slice, ingnoring ascii case.
    pub fn cmp_nocase<B: AsRef<[u8]>>(&self, other: B) -> Ordering {
        let lefts = &self.as_slice();
        let rights = &other.as_ref();
        let left = LowercaseIterator::new(lefts);
        let right = LowercaseIterator::new(rights);
        left.cmp(right)
    }

    /// Compare trimmed bstr with the given slice, ingnoring ascii case.
    pub fn cmp_nocase_trimmed<B: AsRef<[u8]>>(&self, other: B) -> Ordering {
        let lefts = &self.trim_with(|c| c.is_ascii_whitespace());
        let rights = &other.as_ref();
        let left = LowercaseIterator::new(lefts);
        let right = LowercaseIterator::new(rights);
        left.cmp(right)
    }

    /// Return true if self is equal to other ignoring ascii case
    pub fn eq_nocase<B: AsRef<[u8]>>(&self, other: B) -> bool {
        self.cmp_nocase(other) == Ordering::Equal
    }

    /// Case insensitive comparison between self and other, ignoring any zeros in self
    pub fn cmp_nocase_nozero<B: AsRef<[u8]>>(&self, other: B) -> Ordering {
        let lefts = &self.as_slice();
        let rights = &other.as_ref();
        let left = LowercaseNoZeroIterator::new(lefts);
        let right = LowercaseIterator::new(rights);
        left.cmp(right)
    }

    /// Case insensitive comparison between trimmed self and other, ignoring any zeros in self
    pub fn cmp_nocase_nozero_trimmed<B: AsRef<[u8]>>(&self, other: B) -> Ordering {
        let lefts = &self.trim();
        let rights = &other.as_ref();
        let left = LowercaseNoZeroIterator::new(lefts);
        let right = LowercaseIterator::new(rights);
        left.cmp(right)
    }

    /// Return true if self is equal to other, ignoring ascii case and zeros in self
    pub fn eq_nocase_nozero<B: AsRef<[u8]>>(&self, other: B) -> bool {
        self.cmp_nocase_nozero(other) == Ordering::Equal
    }

    /// Extend this bstr with the given slice
    pub fn add<B: AsRef<[u8]>>(&mut self, other: B) {
        self.extend_from_slice(other.as_ref())
    }

    /// Extend the bstr as much as possible without growing
    pub fn add_noex<B: AsRef<[u8]>>(&mut self, other: B) {
        let len = std::cmp::min(self.capacity() - self.len(), other.as_ref().len());
        self.add(&other.as_ref()[..len]);
    }

    /// Return true if this bstr starts with other
    pub fn starts_with<B: AsRef<[u8]>>(&self, other: B) -> bool {
        self.as_slice().starts_with(other.as_ref())
    }

    /// Return true if this bstr starts with other, ignoring ascii case
    pub fn starts_with_nocase<B: AsRef<[u8]>>(&self, other: B) -> bool {
        if self.len() < other.as_ref().len() {
            return false;
        }
        let len: usize = std::cmp::min(self.len(), other.as_ref().len());
        self.as_slice()[..len].eq_ignore_ascii_case(&other.as_ref()[..len])
    }

    /// Find the index of the given slice
    pub fn index_of<B: AsRef<[u8]>>(&self, other: B) -> Option<usize> {
        self.find(other.as_ref())
    }

    /// Find the index of the given slice ignoring ascii case
    pub fn index_of_nocase<B: AsRef<[u8]>>(&self, other: B) -> Option<usize> {
        let src = self.as_slice();
        let mut haystack = LowercaseIterator::new(&src);
        let needle = other.as_ref().to_ascii_lowercase();
        haystack.index_of(&needle)
    }

    /// Find the index of the given slice ignoring ascii case and any zeros in self
    pub fn index_of_nocase_nozero<B: AsRef<[u8]>>(&self, other: B) -> Option<usize> {
        let src = self.as_slice();
        let mut haystack = LowercaseNoZeroIterator::new(&src);
        let needle = other.as_ref().to_ascii_lowercase();
        haystack.index_of(&needle)
    }
}

// Trait Implementations for Bstr

/// Let callers access BString functions
impl Deref for Bstr {
    type Target = BString;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}

/// Let callers access mutable BString functions
impl DerefMut for Bstr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

impl From<&[u8]> for Bstr {
    fn from(src: &[u8]) -> Self {
        Bstr {
            s: BString::from(src),
        }
    }
}

impl From<&str> for Bstr {
    fn from(src: &str) -> Self {
        src.as_bytes().into()
    }
}

impl From<Vec<u8>> for Bstr {
    fn from(src: Vec<u8>) -> Self {
        Bstr {
            s: BString::from(src),
        }
    }
}

/// Compare a Bstr to a &str byte for byte
impl PartialEq<&str> for Bstr {
    fn eq(&self, rhs: &&str) -> bool {
        self.as_bytes() == rhs.as_bytes()
    }
}

/// A trait that lets us find the byte index of slices in a generic way.
///
/// This layer of abstraction is motivated by the need to find needle in
/// haystack when we want to perform case sensitive, case insensitive, and
/// case insensitive + zero skipping. All of these algorithms are identical
/// except we compare the needle bytes with the src bytes in different ways,
/// and in the case of zero skipping we want to pretend that zero bytes in
/// the haystack do not exist. So we define iterators for each of lowercase
/// and lowercase + zero skipping, and then implement this trait for both of
/// those, and then define the search function in terms of this trait.
trait SubIterator: Iterator<Item = u8> {
    /// Return a new iterator of the same type starting at the current byte index
    fn subiter(&self) -> Self;
    /// Return the current byte index into the iterator
    fn index(&self) -> usize;
    /// Find the given needle in self and return the byte index
    fn index_of(&mut self, needle: impl AsRef<[u8]>) -> Option<usize>;
}

/// Find the byte index of the given slice in the source.
///
/// Someday an enterprising soul can implement this function inside SubIterator
/// directly (where it arguably belongs), but this involves handling dyn Self,
/// and implementing it this way lets monomorphization emit concrete
/// implementations for each of the two types we actually have.
fn index_of<T: SubIterator, S: AsRef<[u8]>>(haystack: &mut T, needle: &S) -> Option<usize> {
    let first = needle.as_ref().first()?;
    while let Some(s) = haystack.next() {
        if s == *first {
            let mut test = haystack.subiter();
            let mut equal = false;
            for cmp_byte in needle.as_ref().as_bytes() {
                equal = Some(*cmp_byte) == test.next();
                if !equal {
                    break;
                }
            }
            if equal {
                return Some(haystack.index());
            }
        }
    }
    None
}

/// A convenience iterator for anything that satisfies AsRef<[u8]>
/// that yields lowercase ascii bytes and skips null bytes
struct LowercaseNoZeroIterator<'a, T: AsRef<[u8]>> {
    src: &'a T,
    idx: usize,
    first: bool,
}

impl<'a, T: AsRef<[u8]>> LowercaseNoZeroIterator<'a, T> {
    fn new(src: &'a T) -> Self {
        LowercaseNoZeroIterator {
            src,
            idx: 0,
            first: true,
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for LowercaseNoZeroIterator<'_, T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.first {
                self.first = false;
            } else {
                self.idx += 1;
            }
            let next = self
                .src
                .as_ref()
                .get(self.idx)
                .map(|c| c.to_ascii_lowercase());
            if next != Some(0) {
                break next;
            }
        }
    }
}

impl<T: AsRef<[u8]>> SubIterator for LowercaseNoZeroIterator<'_, T> {
    fn subiter(&self) -> Self {
        LowercaseNoZeroIterator {
            src: self.src,
            idx: self.idx,
            first: true,
        }
    }

    fn index(&self) -> usize {
        self.idx
    }

    fn index_of(&mut self, needle: impl AsRef<[u8]>) -> Option<usize> {
        index_of(self, &needle)
    }
}

/// A convenience iterator for anything that satisfies AsRef<[u8]>
/// that yields lowercase ascii bytes
struct LowercaseIterator<'a, T: AsRef<[u8]>> {
    src: &'a T,
    idx: usize,
    first: bool,
}

impl<'a, T: AsRef<[u8]>> LowercaseIterator<'a, T> {
    fn new(src: &'a T) -> Self {
        LowercaseIterator {
            src,
            idx: 0,
            first: true,
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for LowercaseIterator<'_, T> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
        } else {
            self.idx += 1;
        }
        self.src
            .as_ref()
            .get(self.idx)
            .map(|c| c.to_ascii_lowercase())
    }
}

impl<T: AsRef<[u8]>> SubIterator for LowercaseIterator<'_, T> {
    fn subiter(&self) -> Self {
        LowercaseIterator {
            src: self.src,
            idx: self.idx,
            first: true,
        }
    }

    fn index(&self) -> usize {
        self.idx
    }

    fn index_of(&mut self, needle: impl AsRef<[u8]>) -> Option<usize> {
        index_of(self, &needle)
    }
}

#[cfg(test)]
mod tests {
    use crate::bstr::*;
    use core::cmp::Ordering;
    use rstest::rstest;

    #[test]
    fn Compare() {
        let b = Bstr::from("ABCDefgh");
        // direct equality
        assert_eq!(Ordering::Equal, b.cmp_slice("ABCDefgh"));
        // case sensitive
        assert_ne!(Ordering::Equal, b.cmp_slice("abcdefgh"));
        // src shorter than dst
        assert_eq!(Ordering::Less, b.cmp_slice("ABCDefghi"));
        // src longer than dst
        assert_eq!(Ordering::Greater, b.cmp_slice("ABCDefg"));
        // case less
        assert_eq!(Ordering::Less, b.cmp_slice("abcdefgh"));
        // case greater
        assert_eq!(Ordering::Greater, b.cmp_slice("ABCDEFGH"));
    }

    #[test]
    fn CompareNocase() {
        let b = Bstr::from("ABCDefgh");
        assert_eq!(Ordering::Equal, b.cmp_nocase("ABCDefgh"));
        assert_eq!(Ordering::Equal, b.cmp_nocase("abcdefgh"));
        assert_eq!(Ordering::Equal, b.cmp_nocase("ABCDEFGH"));
        assert_eq!(Ordering::Less, b.cmp_nocase("ABCDefghi"));
        assert_eq!(Ordering::Greater, b.cmp_nocase("ABCDefg"));
    }

    #[test]
    fn CompareNocaseNozero() {
        // nocase_nozero only applies to the source string. The caller
        // is not expected to pass in a search string with nulls in it.
        let b = Bstr::from("A\x00B\x00\x00C\x00Defg\x00h");
        assert_eq!(Ordering::Equal, b.cmp_nocase_nozero("ABCDefgh"));
        assert_eq!(Ordering::Equal, b.cmp_nocase_nozero("abcdefgh"));
        assert_eq!(Ordering::Equal, b.cmp_nocase_nozero("ABCDEFGH"));
        assert_eq!(Ordering::Less, b.cmp_nocase_nozero("ABCDefghi"));
        assert_eq!(Ordering::Greater, b.cmp_nocase_nozero("ABCDefg"));
    }

    #[rstest]
    #[case("abc", "defgh", "abcdefgh")]
    #[case("ABC", "DEFGH", "ABCDEFGH")]
    #[case("aBc", "Defgh", "aBcDefgh")]
    #[case(
        "TestLongerDataBc",
        "Defghikjlmnopqrstuvwxyz",
        "TestLongerDataBcDefghikjlmnopqrstuvwxyz"
    )]
    fn test_add(#[case] input: &str, #[case] input_add: &str, #[case] expected: &str) {
        let mut b = Bstr::from(input);
        b.add(input_add);
        assert_eq!(b.cmp_slice(expected), Ordering::Equal);
    }

    #[rstest]
    #[case(10, "abcd", "efghij", "abcdefghij")]
    #[case(5, "ABcd", "efgh", "ABcde")]
    #[case(4, "AbCd", "EFGH", "AbCd")]
    #[case(20, "abcd", "efGHij", "abcdefGHij")]
    fn test_add_no_ex(
        #[case] capacity: usize,
        #[case] input: &str,
        #[case] input_add: &str,
        #[case] expected: &str,
    ) {
        let mut b = Bstr::with_capacity(capacity);
        b.add_noex(input);
        b.add_noex(input_add);
        assert_eq!(b.cmp_slice(expected), Ordering::Equal);
    }

    #[test]
    fn StartsWith() {
        let b = Bstr::from("ABCD");
        assert!(b.starts_with("AB"));
        assert!(!b.starts_with("ab"));
        assert!(!b.starts_with("Ab"));
        assert!(!b.starts_with("aB"));
        assert!(!b.starts_with("CD"));
    }

    #[test]
    fn StartsWithNocase() {
        let b = Bstr::from("ABCD");
        assert!(b.starts_with_nocase("AB"));
        assert!(b.starts_with_nocase("ab"));
        assert!(b.starts_with_nocase("Ab"));
        assert!(b.starts_with_nocase("aB"));
        assert!(!b.starts_with_nocase("CD"));
    }

    #[test]
    fn IndexOf() {
        let b = Bstr::from("ABCDefgh");
        assert_eq!(Some(4), b.index_of("e"));
        assert_eq!(Some(0), b.index_of("A"));
        assert_eq!(Some(7), b.index_of("h"));
        assert_eq!(Some(3), b.index_of("De"));
        assert_eq!(None, b.index_of("z"));
        assert_eq!(None, b.index_of("a"));
        assert_eq!(None, b.index_of("hi"));
    }

    #[test]
    fn IndexOfNocase() {
        let b = Bstr::from("ABCDefgh");
        assert_eq!(Some(4), b.index_of_nocase("E"));
        assert_eq!(Some(0), b.index_of_nocase("a"));
        assert_eq!(Some(0), b.index_of_nocase("A"));
        assert_eq!(Some(7), b.index_of_nocase("H"));
        assert_eq!(Some(3), b.index_of_nocase("dE"));
        assert_eq!(None, b.index_of_nocase("z"));
        assert_eq!(None, b.index_of_nocase("Hi"));
    }

    #[test]
    fn IndexOfNocaseNozero() {
        let b = Bstr::from("A\x00B\x00\x00C\x00Defg\x00h");
        assert_eq!(Some(8), b.index_of_nocase_nozero("E"));
        assert_eq!(Some(0), b.index_of_nocase_nozero("a"));
        assert_eq!(Some(0), b.index_of_nocase_nozero("A"));
        assert_eq!(Some(12), b.index_of_nocase_nozero("H"));
        assert_eq!(Some(7), b.index_of_nocase_nozero("dE"));
        assert_eq!(Some(2), b.index_of_nocase_nozero("bc"));
        assert_eq!(None, b.index_of_nocase_nozero("z"));
        assert_eq!(None, b.index_of_nocase_nozero("Hi"));
        assert_eq!(None, b.index_of_nocase_nozero("ghi"));
    }
}
