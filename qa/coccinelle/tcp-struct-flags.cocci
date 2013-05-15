@flags@
TcpSession *ssn;
identifier ssn_flags =~ "^(?!STREAMTCP_FLAG).+";
TcpStream *stream;
identifier stream_flags =~ "^(?!STREAMTCP_STREAM_FLAG).+";
TcpSegment *segment;
identifier segment_flags =~ "^(?!SEGMENTTCP_FLAG)_.+";
position p1;
@@

(
ssn->flags@p1 |= ssn_flags
|
ssn->flags@p1 & ssn_flags
|
ssn->flags@p1 &= ~ssn_flags
|
stream->flags@p1 |= stream_flags
|
stream->flags@p1 & stream_flags
|
stream->flags@p1 &= ~stream_flags
|
segment->flags@p1 |= segment_flags
|
segment->flags@p1 &= ~segment_flags
|
segment->flags@p1 & segment_flags
)


@script:python@
p1 << flags.p1;
@@

print "Invalid usage of flags field at %s:%s, flags value is incorrect (wrong family)." % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
