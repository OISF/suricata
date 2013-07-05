@flags@
TcpSegment *struct0;
identifier struct_flags0 =~ "^(?!SEGMENTTCP_FLAG).+";
TcpStream *struct1;
identifier struct_flags1 =~ "^(?!STREAMTCP_STREAM_FLAG_).+";
TcpSession *struct2;
identifier struct_flags2 =~ "^(?!STREAMTCP_FLAG).+";
Packet *struct3;
identifier struct_flags3 =~ "^(?!FLOW_PKT_).+";
SignatureHeader *struct4;
identifier struct_flags4 =~ "^(?!SIG_FLAG).+";
Signature *struct5;
identifier struct_flags5 =~ "^(?!SIG_FLAG).+";
Signature *struct6;
identifier struct_flags6 =~ "^(?!SIG_FLAG_INIT_).+";
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
struct2->flags@p1 |= struct_flags2
|
struct2->flags@p1 & struct_flags2
|
struct2->flags@p1 &= ~struct_flags2
|
struct3->flowflags@p1 |= struct_flags3
|
struct3->flowflags@p1 & struct_flags3
|
struct3->flowflags@p1 &= ~struct_flags3
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
struct6->init_flags@p1 |= struct_flags6
|
struct6->init_flags@p1 & struct_flags6
|
struct6->init_flags@p1 &= ~struct_flags6
)

@script:python@
p1 << flags.p1;
@@

print "Invalid usage of flags field at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
