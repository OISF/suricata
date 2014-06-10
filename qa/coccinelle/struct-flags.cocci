@flags@
SignatureHeader *struct0;
identifier struct_flags0 =~ "^(?!SIG_FLAG).+";
Signature *struct1;
identifier struct_flags1 =~ "^(?!SIG_FLAG).+";
Signature *struct2;
identifier struct_flags2 =~ "^(?!SIG_FLAG_INIT_).+";
Flow *struct3;
identifier struct_flags3 =~ "^(?!FLOW_).+";
TcpSegment *struct4;
identifier struct_flags4 =~ "^(?!SEGMENTTCP_FLAG).+";
TcpStream *struct5;
identifier struct_flags5 =~ "^(?!STREAMTCP_STREAM_FLAG_).+";
TcpSession *struct6;
identifier struct_flags6 =~ "^(?!STREAMTCP_FLAG).+";
Packet *struct7;
identifier struct_flags7 =~ "^(?!FLOW_PKT_).+";
position p1;
@@

(
struct0->flags@p1 |= struct_flags0
|
struct0->flags@p1 & struct_flags0
|
struct0->flags@p1 &= ~struct_flags0
|
struct1->flags@p1 |= struct_flags1
|
struct1->flags@p1 & struct_flags1
|
struct1->flags@p1 &= ~struct_flags1
|
struct2->init_flags@p1 |= struct_flags2
|
struct2->init_flags@p1 & struct_flags2
|
struct2->init_flags@p1 &= ~struct_flags2
|
struct3->flags@p1 |= struct_flags3
|
struct3->flags@p1 & struct_flags3
|
struct3->flags@p1 &= ~struct_flags3
|
struct4->flags@p1 |= struct_flags4
|
struct4->flags@p1 & struct_flags4
|
struct4->flags@p1 &= ~struct_flags4
|
struct5->flags@p1 |= struct_flags5
|
struct5->flags@p1 & struct_flags5
|
struct5->flags@p1 &= ~struct_flags5
|
struct6->flags@p1 |= struct_flags6
|
struct6->flags@p1 & struct_flags6
|
struct6->flags@p1 &= ~struct_flags6
|
struct7->flowflags@p1 |= struct_flags7
|
struct7->flowflags@p1 & struct_flags7
|
struct7->flowflags@p1 &= ~struct_flags7
)

@script:python@
p1 << flags.p1;
@@

print "Invalid usage of flags field at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
