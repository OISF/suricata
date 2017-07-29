@uint@
uint i;
position p1;
@@

i@p1

@script:python@
p1 << uint.p1;
@@
print "banned type uint used at at %s:%s, please use a explicit length." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
