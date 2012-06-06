/*
-------------------------------------------------------------------------------
lookup3.c, by Bob Jenkins, May 2006, Public Domain.

These are functions for producing 32-bit hashes for hash table lookup.
hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final() 
are externally useful functions.  Routines to test the hash are included 
if SELF_TEST is defined.  You can use this free for any purpose.  It's in
the public domain.  It has no warranty.

You probably want to use hashlittle().  hashlittle() and hashbig()
hash byte arrays.  hashlittle() is is faster than hashbig() on
little-endian machines.  Intel and AMD are little-endian machines.
On second thought, you probably want hashlittle2(), which is identical to
hashlittle() except it returns two 32-bit hashes for the price of one.  
You could implement hashbig2() if you wanted but I haven't bothered here.

If you want to find a hash of, say, exactly 7 integers, do
  a = i1;  b = i2;  c = i3;
  mix(a,b,c);
  a += i4; b += i5; c += i6;
  mix(a,b,c);
  a += i7;
  final(a,b,c);
then use c as the hash value.  If you have a variable length array of
4-byte integers to hash, use hashword().  If you have a byte array (like
a character string), use hashlittle().  If you have several byte arrays, or
a mix of things, see the comments above hashlittle().  

Why is this so big?  I read 12 bytes at a time into 3 4-byte integers, 
then mix those integers.  This is fast (you can do a lot more thorough
mixing with 12*3 instructions on 3 integers than you can with 3 instructions
on 1 byte), but shoehorning those bytes into integers efficiently is messy.
-------------------------------------------------------------------------------
*/

#ifndef __UTIL_HASH_LOOKUP3_H__
#define __UTIL_HASH_LOOKUP3_H__

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

uint32_t hashword(const uint32_t *k,        /* the key, an array of uint32_t values */
                  size_t          length,   /* the length of the key, in uint32_ts */
                  uint32_t        initval); /* the previous hash, or an arbitrary value */


void hashword2 (const uint32_t *k,          /* the key, an array of uint32_t values */
                size_t          length,     /* the length of the key, in uint32_ts */
                uint32_t       *pc,         /* IN: seed OUT: primary hash value */
                uint32_t       *pb);        /* IN: more seed OUT: secondary hash value */

uint32_t hashlittle( const void *key, size_t length, uint32_t initval);

void hashlittle2(const void *key,       /* the key to hash */
                 size_t      length,    /* length of the key */
                 uint32_t   *pc,        /* IN: primary initval, OUT: primary hash */
                 uint32_t   *pb);       /* IN: secondary initval, OUT: secondary hash */

uint32_t hashbig( const void *key, size_t length, uint32_t initval);

#endif /* __UTIL_HASH_LOOKUP3_H__ */

