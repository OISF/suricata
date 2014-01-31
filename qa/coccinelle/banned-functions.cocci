@banned@
identifier func =~ "^(sprintf|strcat|strcpy|strncpy|strncat|strndup|strchrdup)$";
position p1;
@@

<+...
func(...)@p1
...+>

@ script:python @
p1 << banned.p1;
func << banned.func;
@@

print "Banned function %s() used at %s:%s" % (func, p1[0].file, p1[0].line)
import sys
sys.exit(1)
