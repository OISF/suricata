#ifndef __DETECT_PARSE_H__
#define __DETECT_PARSE_H__

/** Flags to indicate if the Signature parsing must be done
*   switching the source and dest (for ip addresses and ports)
*   or otherwise as normal */
enum {
    SIG_DIREC_NORMAL,
    SIG_DIREC_SWITCHED
};

/** Flags to indicate if are referencing the source of the Signature
*   or the destination (for ip addresses and ports)*/
enum {
    SIG_DIREC_SRC,
    SIG_DIREC_DST
};

/* prototypes */
int SigParse(DetectEngineCtx *,Signature *, char *, uint8_t);
Signature *SigAlloc (void);
void SigFree(Signature *s);
Signature *SigInit(DetectEngineCtx *,char *sigstr);
SigMatch *SigMatchGetLastSM(Signature *, uint8_t);
void SigParsePrepare(void);
void SigParseRegisterTests(void);
Signature *DetectEngineAppendSig(DetectEngineCtx *, char *);
void SigMatchReplace (Signature *, SigMatch *, SigMatch *);
#endif /* __DETECT_PARSE_H__ */

