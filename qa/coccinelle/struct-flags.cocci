@flags@
SignatureInitData *struct0;
identifier struct_flags0 =~ "^(?!SIG_FLAG_INIT_).+";
Signature *struct1;
identifier struct_flags1 =~ "^(?!SIG_FLAG).+";
Flow *struct2;
identifier struct_flags2 =~ "^(?!FLOWFILE_).+";
Flow *struct3;
identifier struct_flags3 =~ "^(?!FLOW_END_FLAG_).+";
TcpStream *struct4;
identifier struct_flags4 =~ "^(?!STREAMTCP_STREAM_FLAG_).+";
TcpSession *struct5;
identifier struct_flags5 =~ "^(?!STREAMTCP_FLAG).+";
TcpStreamCnf *struct6;
identifier struct_flags6 =~ "^(?!STREAMTCP_INIT_).+";
Packet *struct7;
identifier struct_flags7 =~ "^(?!FLOW_PKT_).+";
position p1;
@@

(
struct0->init_flags@p1 |= struct_flags0
|
struct0->init_flags@p1 & struct_flags0
|
struct0->init_flags@p1 &= ~struct_flags0
|
struct1->flags@p1 |= struct_flags1
|
struct1->flags@p1 & struct_flags1
|
struct1->flags@p1 &= ~struct_flags1
|
struct2->file_flags@p1 |= struct_flags2
|
struct2->file_flags@p1 & struct_flags2
|
struct2->file_flags@p1 &= ~struct_flags2
|
struct3->flow_end_flags@p1 |= struct_flags3
|
struct3->flow_end_flags@p1 & struct_flags3
|
struct3->flow_end_flags@p1 &= ~struct_flags3
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
