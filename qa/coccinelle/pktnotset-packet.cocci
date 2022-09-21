@zeroed@
typedef Packet;
typedef uint8_t;
Packet *p;
position p1;
@@

memset(p@p1, 0, ...);

@isset@
Packet *p;
position zeroed.p1;
@@

memset(p@p1, 0, ...);
... when != p
(
p->pkt
|
PacketInit(p)
)

@script:python depends on !isset@
p1 << zeroed.p1;
@@

print("Packet zeroed at %s:%s but pkt field is not set afterward." % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
