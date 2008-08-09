#ifndef __DETECT_PARSE_H__
#define __DETECT_PARSE_H__

/* prototypes */
int SigParse(Signature *s, char *sigstr);
Signature *SigAlloc (void);
void SigFree(Signature *s);
Signature *SigInit(char *sigstr);
void SigParsePrepare(void);

#endif /* __DETECT_PARSE_H__ */

