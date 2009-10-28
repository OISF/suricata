#ifndef __DETECT_PORT_H__
#define __DETECT_PORT_H__

/* prototypes */
void DetectPortRegister (void);

int DetectPortParse(DetectPort **head, char *str);

DetectPort *DetectPortCopy(DetectEngineCtx *, DetectPort *);
DetectPort *DetectPortCopySingle(DetectEngineCtx *, DetectPort *);
int DetectPortInsertCopy(DetectEngineCtx *,DetectPort **, DetectPort *);
int DetectPortInsert(DetectEngineCtx *,DetectPort **, DetectPort *);
void DetectPortCleanupList (DetectPort *head);

DetectPort *DetectPortLookup(DetectPort *head, DetectPort *dp);
int DetectPortAdd(DetectPort **head, DetectPort *dp);

DetectPort *DetectPortLookupGroup(DetectPort *dp, uint16_t port);

void DetectPortPrintMemory(void);

DetectPort *DetectPortDpHashLookup(DetectEngineCtx *, DetectPort *);
DetectPort *DetectPortDpHashGetListPtr(DetectEngineCtx *);
int DetectPortDpHashInit(DetectEngineCtx *);
void DetectPortDpHashFree(DetectEngineCtx *);
int DetectPortDpHashAdd(DetectEngineCtx *, DetectPort *);
void DetectPortDpHashReset(DetectEngineCtx *);

DetectPort *DetectPortSpHashLookup(DetectEngineCtx *, DetectPort *);
int DetectPortSpHashInit(DetectEngineCtx *);
void DetectPortSpHashFree(DetectEngineCtx *);
int DetectPortSpHashAdd(DetectEngineCtx *, DetectPort *);
void DetectPortSpHashReset(DetectEngineCtx *);

int DetectPortJoin(DetectEngineCtx *,DetectPort *target, DetectPort *source);

void DetectPortPrint(DetectPort *);
void DetectPortPrintList(DetectPort *head);
int DetectPortCmp(DetectPort *, DetectPort *);
void DetectPortFree(DetectPort *);

#endif /* __DETECT_PORT_H__ */

