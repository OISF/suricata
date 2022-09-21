@sizet@
size_t p;
identifier func =~ "^(sprintf|printf|SCLog.*)$";
identifier funcn =~ "^.*nprintf$";
position p1;
typedef uint16_t;
typedef uint32_t;
typedef uint64_t;
expression E1, E2;
@@

(
func(..., p, ...)@p1;
|
func(..., (int) p, ...)@p1;
|
func(..., (unsigned int) p, ...)@p1;
|
func(..., (uint16_t) p, ...)@p1;
|
func(..., (uint32_t) p, ...)@p1;
|
func(..., (uint64_t) p, ...)@p1;
|
funcn(E1, E2,..., p, ...)@p1;
|
funcn(E1, E2,..., (int) p, ...)@p1;
|
funcn(E1, E2,..., (unsigned int) p, ...)@p1;
|
funcn(E1, E2,..., (uint16_t) p, ...)@p1;
|
funcn(E1, E2,..., (uint32_t) p, ...)@p1;
|
funcn(E1, E2,..., (uint64_t) p, ...)@p1;
)

@ script:python @
p1 << sizet.p1;
@@

print("Invalid printf with size_t (not casted to uintmax_t) at %s:%s" % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
