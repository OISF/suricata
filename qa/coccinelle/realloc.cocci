@realloc@
expression x, E;
type ty;
position p1;
@@

(
x@p1 = SCRealloc(x, E)
|
x@p1 = (ty *) SCRealloc(x, E)
)

@script:python@
p1 << realloc.p1;
@@
print("Structure reallocated at %s:%s but original pointer is lost and not freed in case of error." % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
