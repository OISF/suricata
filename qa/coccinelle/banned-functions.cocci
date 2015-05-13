@banned@
identifier i;
position p1;
@@

\(strtok@i\|sprintf@i\|strcat@i\|strcpy@i\|strncpy@i\|strncat@i\|strndup@i\|strchrdup@i\)(...)@p1

@script:python@
p1 << banned.p1;
i << banned.i;
@@

print("Banned function '%s' used at %s:%s" % (i, p1[0].file, p1[0].line))
import sys
sys.exit(1)
