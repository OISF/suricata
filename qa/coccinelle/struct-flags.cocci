@flags@
LogFileCtx *struct0;
identifier struct_flags0 =~ "^(?!LOGFILE_LOG).+";
Packet *struct1;
identifier struct_flags1 =~ "^(?!FLOW_PKT_).+";
SignatureInitData *struct2;
identifier struct_flags2 =~ "^(?!SIG_FLAG_INIT_).+";
Signature *struct3;
identifier struct_flags3 =~ "^(?!SIG_FLAG).+";
TcpSegment *struct4;
identifier struct_flags4 =~ "^(?!SEGMENTTCP_FLAG).+";
TcpStream *struct5;
identifier struct_flags5 =~ "^(?!STREAMTCP_STREAM_FLAG_).+";
TcpSession *struct6;
identifier struct_flags6 =~ "^(?!STREAMTCP_FLAG).+";
Flow *struct7;
identifier struct_flags7 =~ "^(?!FLOWFILE_).+";
Flow *struct8;
identifier struct_flags8 =~ "^(?!FLOW_END_FLAG_).+";
position p1;
@@

(
struct0->option_flags@p1 |= struct_flags0
|
struct0->option_flags@p1 & struct_flags0
|
struct0->option_flags@p1 &= ~struct_flags0
|
struct1->flowflags@p1 |= struct_flags1
|
struct1->flowflags@p1 & struct_flags1
|
struct1->flowflags@p1 &= ~struct_flags1
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
struct7->file_flags@p1 |= struct_flags7
|
struct7->file_flags@p1 & struct_flags7
|
struct7->file_flags@p1 &= ~struct_flags7
|
struct8->flow_end_flags@p1 |= struct_flags8
|
struct8->flow_end_flags@p1 & struct_flags8
|
struct8->flow_end_flags@p1 &= ~struct_flags8
)

@script:python@
p1 << flags.p1;
@@

print "Invalid usage of flags field at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
