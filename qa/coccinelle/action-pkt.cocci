@action@
typedef Packet;
Packet *p;
position p1;
@@

p->action@p1

@ script:python @
p1 << action.p1;
@@

print("Invalid usage of p->action, please use macro at %s:%s" % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
