@malloced@
expression x;
position p1;
identifier func =~ "(SCMalloc|SCStrdup|SCCalloc|SCMallocAligned|SCRealloc)";
@@

x@p1 = func(...)

@inlinetested@
expression x, E;
statement S;
position malloced.p1;
identifier func =~ "(SCMalloc|SCStrdup|SCCalloc|SCMallocAligned|SCRealloc)";
@@

(
if ((x@p1 = func(...)) == NULL) S
|
if (E && (x@p1 = func(...)) == NULL) S
)

@realloc exists@
position malloced.p1;
expression x, E1;
identifier func =~ "(SCMalloc|SCCalloc|SCMallocAligned)";
@@

x@p1 = func(...)
... when != x
x = SCRealloc(x, E1)

@istested depends on !realloc exists@
expression x, E1;
position malloced.p1;
statement S1, S2;
identifier func =~ "(SCMalloc|SCStrdup|SCCalloc|SCMallocAligned|SCRealloc)";
@@

x@p1 = func(...)
... when != x
(
if (unlikely(x == NULL)) S1
|
if (unlikely(x == NULL)) S1 else S2
|
if (likely(x != NULL)) S1
|
if (x == NULL) S1
|
if (x != NULL) S1 else S2
|
if (x && E1) S1
|
BUG_ON(x == NULL)
|
FAIL_IF(x == NULL)
|
FAIL_IF(unlikely(x == NULL))
|
FAIL_IF_NULL(x)
)


@script:python depends on !realloc && !istested && !inlinetested@
p1 << malloced.p1;
@@
print("Structure malloced at %s:%s but error is not checked." % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
