@siginit@
identifier func =~ "Detect.*Setup";
expression E1;
position p1;
identifier de_ctx, s, str, error;
type DetectEngineCtx, Signature;
@@

func(DetectEngineCtx *de_ctx, Signature *s, char *str) {
...
SigMatchAppendSMToList(s, ...)@p1;
...
if (s->alproto != E1 && ...) {
...
goto error;
}
...
}


@script:python@
p1 << siginit.p1;
@@
print("SigMatch added at %s:%s but error handling can cause it to be freed later." % (p1[0].file, p1[0].line))
import sys
sys.exit(1)
