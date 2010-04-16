#ifndef __DETECT_ENGINE_IPONLY_H__
#define __DETECT_ENGINE_IPONLY_H__

/**
 * SigNumArray is a bit array representing signatures
 * it can be used linked to src/dst address to indicate
 * which signatures apply to this addres
 * at IP Only we store SigNumArrays at the radix trees
 */
typedef struct SigNumArray_ {
    uint8_t *array; /* bit array of sig nums */
    uint32_t size;  /* size in bytes of the array */
}SigNumArray;

IPOnlyCIDRItem *IPOnlyCIDRItemNew();

IPOnlyCIDRItem *IPOnlyCIDRItemInsertReal(IPOnlyCIDRItem *head, IPOnlyCIDRItem *item);
IPOnlyCIDRItem *IPOnlyCIDRItemInsert(IPOnlyCIDRItem *head, IPOnlyCIDRItem *item);

void IPOnlyCIDRListFree(IPOnlyCIDRItem *tmphead);
void IPOnlyCIDRListPrint(IPOnlyCIDRItem *tmphead);

IPOnlyCIDRItem *IPOnlyCIDRListParse2(char *s, int negate);

int IPOnlyCIDRListParse(IPOnlyCIDRItem **gh, char *str);
int IPOnlySigParseAddress(Signature *s, const char *addrstr, char flag);
int IPOnlyCIDRItemParseSingle(IPOnlyCIDRItem *dd, char *str);
int IPOnlyCIDRItemSetup(IPOnlyCIDRItem *gh, char *s);

void IPOnlyCIDRListPrint(IPOnlyCIDRItem *);
void IPOnlyMatchPacket(DetectEngineCtx *, DetectEngineThreadCtx *,
                       DetectEngineIPOnlyCtx *, DetectEngineIPOnlyThreadCtx *,
                       Packet *);
void IPOnlyInit(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyPrint(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyDeinit(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyPrepare(DetectEngineCtx *);
void DetectEngineIPOnlyThreadInit(DetectEngineCtx *, DetectEngineIPOnlyThreadCtx *);
void DetectEngineIPOnlyThreadDeinit(DetectEngineIPOnlyThreadCtx *);
void IPOnlyAddSignature(DetectEngineCtx *, DetectEngineIPOnlyCtx *, Signature *);
void IPOnlyRegisterTests(void);

#endif /* __DETECT_ENGINE_IPONLY_H__ */

