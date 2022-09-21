@init@
typedef Packet;
Packet *p;
expression E;
statement S;
@@

(
memset(p, ...);
p->pkt = E;
|
p = SCCalloc(...);
S
p->pkt = E;
)

@pktfield depends on !init@
identifier func !~ "^PacketCopyDataOffset$";
Packet *p;
position p1;
@@

func(...) {
<...
p->pkt@p1
...>
}

@ script:python @
p1 << pktfield.p1;
@@

print("Invalid Packet->pkt usage, GET_PKT_DATA macro must be used at %s:%s" % (p1[0].file, p1[0].line))
import sys
sys.exit(1)

@pktlenfield@
identifier func !~ "^PacketCopyDataOffset$";
Packet *p;
position p1;
@@

func(...) {
<...
p->pktlen@p1
...>
}

@ script:python @
p1 << pktlenfield.p1;
@@

print("Invalid Packet->pktlen usage, GET_PKT_LEN macro must be used at %s:%s" % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
