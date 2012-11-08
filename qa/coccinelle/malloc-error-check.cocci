@malloced@
identifier x;
position p1;
identifier func =~ "(SCMalloc|SCStrdup|SCCalloc|SCMallocAligned|SCRealloc)";
@@

x@p1 = func(...)


@inlinetested@
identifier x;
position p1;
statement S;
identifier func =~ "(SCMalloc|SCStrdup|SCCalloc|SCMallocAligned|SCRealloc)";
@@

if ((x@p1 = func(...)) == NULL) S

@istested@
identifier x;
position malloced.p1;
statement S1, S2;
identifier func =~ "(SCMalloc|SCStrdup|SCCalloc|SCMallocAligned|SCRealloc)";
@@

x@p1 = func(...)
... when != x
(
if (unlikely(x == NULL)) S1
|
if (likely(x != NULL)) S1
|
if (x == NULL) S1
|
if (x != NULL) S1 else S2
|
BUG_ON(x == NULL)
)

@script:python depends on malloced && !istested && !inlinetested @
p1 << malloced.p1;
@@

print "Structure malloced at %s:%s but error is not checked." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
