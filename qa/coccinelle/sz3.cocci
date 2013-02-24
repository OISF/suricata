//
//  Take size of pointed value, not pointer
//
// Target: Linux, Generic
// Copyright:  2012 - LIP6/INRIA
// License:  Licensed under GPLv2 or any later version.
// Author: Julia Lawall <Julia.Lawall@lip6.fr>
// URL: http://coccinelle.lip6.fr/
// URL: http://coccinellery.org/
// Modified by Eric Leblond <eric@regit.org> for suricata test system

@preuse@
expression *e;
type T;
identifier f;
position p1;
@@

f(...,
sizeof(e@p1)
,...,(T)e,...)

@ script:python @
p1 << preuse.p1;
@@

print "Size of pointed value not pointer used at %s:%s" % (p1[0].file, p1[0].line)
import sys
sys.exit(1)

@postuse@
expression *e;
type T;
identifier f;
position p1;
@@

f(...,(T)e,...,
sizeof(e@p1)
,...)

@ script:python @
p1 << postuse.p1;
@@

print "Size of pointed value not pointer used at %s:%s" % (p1[0].file, p1[0].line)
import sys
sys.exit(1)
