@directpacket@
identifier p;
typedef Packet;
position p1;
@@

Packet p@p1;

@ script:python @
p1 << directpacket.p1;
@@

print "Invalid Packet definition, explicit allocation must be used at %s:%s" % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
