/* ip only part of the detection engine */

/* TODO: needs a lot of work, for example IPv6 support
 *
 * The dificulty with ip only matching is that we need to support (very large)
 * netblocks as well. So we can't just add every single ip to a hash as that
 * would be consuming to much memory. Thats why I've chosen to have a hash of
 * /16's with a list inside them. If a netblock to add is bigger than a /16, 
 * we split it into /16's.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"

#include "detect-engine-threshold.h"
#include "detect-threshold.h"
#include "util-classification-config.h"

#include "util-debug.h"
#include "util-unittest.h"

/* build a lookup tree for src, if we have one: save
 * build a lookup tree for dst, if we have one: save
 * compare tree's: if they have one (or more) matching
 * sig, we have a match. */

#define IPONLY_EXTRACT_16(a) ((a)->ip[0] & 0x0000ffff)
//#define IPONLY_EXTRACT_24(a) ((a)->ip[0] & 0x00ffffff)

/* No need to calc a constant every lookup: htonl(65535) */
#define IPONLY_HTONL_65535 4294901760UL

static uint32_t IPOnlyHashFunc16(HashListTable *ht, void *data, uint16_t len) {
    DetectAddress *gr = (DetectAddress *) data;

    uint32_t hash = IPONLY_EXTRACT_16(gr) % ht->array_size;
    return hash;
}

/*
static uint32_t IPOnlyHashFunc24(HashListTable *ht, void *data, uint16_t len) {
    DetectAddress *gr = (DetectAddress *) data;

    uint32_t hash = IPONLY_EXTRACT_24(gr->ad) % ht->array_size;
    return hash;
}
*/

static void IPOnlyAddSlash16(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx, HashListTable *ht, DetectAddress *gr, char direction, Signature *s) {
    uint32_t high = ntohl(gr->ip2[0]);
    uint32_t low = ntohl(gr->ip[0]);

    if ((ntohl(gr->ip2[0]) - ntohl(gr->ip[0])) > 65536) {
        //printf("Bigger than a class/16:\n"); DetectAddressDataPrint(gr->ad);

        uint32_t s16_cnt = 0;

        while (high > low) {
            s16_cnt++;

            DetectAddress *grtmp = DetectAddressCopy(gr);
            if (grtmp == NULL) {
                goto error;
            }
            grtmp->ip[0] = htonl(high - 65535);
            grtmp->ip2[0] = htonl(high);

            SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

            DetectAddress *rgr = HashListTableLookup(ht,grtmp,0);
            if (rgr == NULL) {
                SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

                HashListTableAdd(ht,grtmp,0);
                direction ? io_ctx->a_dst_uniq16++ : io_ctx->a_src_uniq16++;
            } else {
                SigGroupHeadAppendSig(de_ctx, &rgr->sh, s);

                DetectAddressFree(grtmp);
                direction ? io_ctx->a_dst_total16++ : io_ctx->a_src_total16++;
            }

            if (high >= 65536)
                high -= 65536;
            else
                high = 0;
        }
    } else {
        DetectAddress *grtmp = DetectAddressCopy(gr);
        if (grtmp == NULL) {
            goto error;
        }
        grtmp->ip[0] = IPONLY_EXTRACT_16(gr);
        grtmp->ip2[0] = IPONLY_EXTRACT_16(gr) | IPONLY_HTONL_65535;

        DetectAddress *rgr = HashListTableLookup(ht,grtmp,0);
        if (rgr == NULL) {
            SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

            HashListTableAdd(ht,grtmp,0);
            direction ? io_ctx->a_dst_uniq16++ : io_ctx->a_src_uniq16++;
        } else {
            SigGroupHeadAppendSig(de_ctx, &rgr->sh, s);

            DetectAddressFree(grtmp);
            direction ? io_ctx->a_dst_total16++ : io_ctx->a_src_total16++;
        }
    }
error:
    return;
}

/*
static void IPOnlyAddSlash24(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx, HashListTable *ht, DetectAddress *gr, char direction, Signature *s) {
    if ((ntohl(gr->ad->ip2[0]) - ntohl(gr->ad->ip[0])) > 256) {
        //printf("Bigger than a class/24:\n"); DetectAddressDataPrint(a);

        uint32_t high = ntohl(gr->ad->ip2[0]);
        uint32_t low = ntohl(gr->ad->ip[0]);
        uint32_t s24_cnt = 0;

        while (high > low) {
            s24_cnt++;

            DetectAddress *grtmp = DetectAddressInit();
            if (grtmp == NULL) {
                goto error;
            }
            DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
            if (adtmp == NULL) {
                goto error;
            }
            adtmp->ip[0] = htonl(high - 255);
            adtmp->ip2[0] = htonl(high);
            grtmp->ad = adtmp;
            grtmp->cnt = 1;

            //printf("  -=-  "); DetectAddressDataPrint(na);

            DetectAddress *rgr = HashListTableLookup(ht,grtmp,0);
            if (rgr == NULL) {
                HashListTableAdd(ht,grtmp,0);
                direction ? io_ctx->a_dst_uniq24++ : io_ctx->a_src_uniq24++;
                //printf(" uniq\n");
            } else {
                DetectAddressFree(grtmp);
                direction ? io_ctx->a_dst_total24++ : io_ctx->a_src_total24++;
                //printf(" dup\n");
            }

            if (high >= 256)
                high -= 256;
            else
                high = 0;
        }
        //printf(" contains %" PRIu32 " /24's\n", s24_cnt);

    } else {
        DetectAddress *rgr = HashListTableLookup(ht,gr,0);
        if (rgr == NULL) {
            HashListTableAdd(ht,gr,0);
            direction ? io_ctx->a_dst_uniq24++ : io_ctx->a_src_uniq24++;
        } else {
            direction ? io_ctx->a_dst_total24++ : io_ctx->a_src_total24++;
        }
    }
error:
    return;
}
*/

static char IPOnlyCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2) {
    DetectAddress *a1 = (DetectAddress *)data1;
    DetectAddress *a2 = (DetectAddress *)data2;

    //printf("IPOnlyCompareFunc: "); DetectAddressDataPrint(a1->ad);
    //printf(" "); DetectAddressDataPrint(a2->ad); printf("\n");

    if (DetectAddressCmp(a1,a2) != ADDRESS_EQ)
        return 0;

    return 1;
}


static void IPOnlyFreeFunc(void *g) {
    if (g == NULL)
        return;

    DetectAddress *ag = (DetectAddress *)g;
    DetectAddressFree(ag);
}

/* XXX error checking */
void IPOnlyInit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    io_ctx->ht16_src = HashListTableInit(65536, IPOnlyHashFunc16, IPOnlyCompareFunc, IPOnlyFreeFunc);
    io_ctx->ht16_dst = HashListTableInit(65536, IPOnlyHashFunc16, IPOnlyCompareFunc, IPOnlyFreeFunc);
/*
    io_ctx->ht24_src = HashListTableInit(65536, IPOnlyHashFunc24, IPOnlyCompareFunc, IPOnlyFreeFunc);
    io_ctx->ht24_dst = HashListTableInit(65536, IPOnlyHashFunc24, IPOnlyCompareFunc, IPOnlyFreeFunc);
*/
    io_ctx->sig_init_size = DetectEngineGetMaxSigId(de_ctx) / 8 + 1;
    if ( (io_ctx->sig_init_array = malloc(io_ctx->sig_init_size)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(io_ctx->sig_init_array, 0, io_ctx->sig_init_size);
}

/* XXX error checking */
void DetectEngineIPOnlyThreadInit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyThreadCtx *io_tctx) {
    io_tctx->src = DetectAddressInit();
    io_tctx->src->family = AF_INET;
    io_tctx->dst = DetectAddressInit();
    io_tctx->dst->family = AF_INET;

        /* initialize the signature bitarray */
    io_tctx->sig_match_size = de_ctx->io_ctx.max_idx / 8 + 1;
    io_tctx->sig_match_array = malloc(io_tctx->sig_match_size);
    memset(io_tctx->sig_match_array, 0, io_tctx->sig_match_size);
}

void IPOnlyPrint(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("IP ONLY (SRC): %" PRIu32 " /16's in our hash, %" PRIu32 " total address ranges",
                io_ctx->a_src_uniq16, io_ctx->a_src_uniq16 + io_ctx->a_src_total16);
        SCLogInfo("IP ONLY (DST): %" PRIu32 " /16's in our hash, %" PRIu32 " total address ranges",
                io_ctx->a_dst_uniq16, io_ctx->a_dst_uniq16 + io_ctx->a_dst_total16);
/*
        printf(" * IP ONLY (SRC): %" PRIu32 " /24's in our hash, %" PRIu32 " total address ranges in them\n",
                io_ctx->a_src_uniq24, io_ctx->a_src_uniq24 + io_ctx->a_src_total24);
        printf(" * IP ONLY (DST): %" PRIu32 " /24's in our hash, %" PRIu32 " total address ranges in them\n",
                io_ctx->a_dst_uniq24, io_ctx->a_dst_uniq24 + io_ctx->a_dst_total24);
*/
    }
}

void IPOnlyDeinit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    HashListTableFree(io_ctx->ht16_src);
    io_ctx->ht16_src = NULL;
    HashListTableFree(io_ctx->ht16_dst);
    io_ctx->ht16_dst = NULL;
/*
    HashListTableFree(io_ctx->ht24_src);
    io_ctx->ht24_src = NULL;
    HashListTableFree(io_ctx->ht24_dst);
    io_ctx->ht24_dst = NULL;
*/
    free(io_ctx->sig_init_array);
    io_ctx->sig_init_array = NULL;
}

void DetectEngineIPOnlyThreadDeinit(DetectEngineIPOnlyThreadCtx *io_tctx) {
    if (io_tctx != NULL) {
        if (io_tctx->src != NULL) {
            DetectAddressFree(io_tctx->src);
        }
        if (io_tctx->dst != NULL) {
            DetectAddressFree(io_tctx->dst);
        }
        free(io_tctx->sig_match_array);
    }
}

DetectAddress *IPOnlyLookupSrc16(DetectEngineCtx *de_ctx, DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p) {
    io_tctx->src->ip[0] = GET_IPV4_SRC_ADDR_U32(p) & 0x0000ffff;
    io_tctx->src->ip2[0] = (GET_IPV4_SRC_ADDR_U32(p) & 0x0000ffff) | IPONLY_HTONL_65535;

    //printf("IPOnlyLookupSrc16: "); DetectAddressDataPrint(io_tctx->src->ad); printf("\n");

    DetectAddress *rgr = HashListTableLookup(de_ctx->io_ctx.ht16_src, io_tctx->src, 0);

    return rgr;
}

DetectAddress *IPOnlyLookupDst16(DetectEngineCtx *de_ctx, DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p) {
    io_tctx->dst->ip[0] = GET_IPV4_DST_ADDR_U32(p) & 0x0000ffff;
    io_tctx->dst->ip2[0] = (GET_IPV4_DST_ADDR_U32(p) & 0x0000ffff) | IPONLY_HTONL_65535;

    //printf("IPOnlyLookupDst16: "); DetectAddressDataPrint(io_tctx->dst->ad); printf("\n");

    DetectAddress *rgr = HashListTableLookup(de_ctx->io_ctx.ht16_dst, io_tctx->dst, 0);

    return rgr;
}

/* XXX handle any case: preinit a array with the any's set to 1 for both
 * src and dst, and use that if src/dst is NULL and AND that with the other
 * array. */
void IPOnlyMatchPacket(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx,
                       DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p) {
    DetectAddress *src = NULL, *dst = NULL;
#if 0
    /* debug print */
    char s[16], d[16];
    inet_ntop(AF_INET, (const void *)(p->src.addr_data32), s, sizeof(s));
    inet_ntop(AF_INET, (const void *)(p->dst.addr_data32), d, sizeof(d));
    printf("IPV4 %s->%s\n",s,d);

    printf("IPOnlyMatchPacket starting...\n");
#endif
    if (io_tctx->src == NULL)
        return;

    //printf("IPOnlyMatchPacket looking up src...\n");
    /* lookup source address group */
    src = IPOnlyLookupSrc16(de_ctx, io_tctx, p);
    if (src == NULL || src->sh == NULL)
        return;
    //printf("IPOnlyMatchPacket looking up dst...\n");

    /* lookup source address group */
    dst = IPOnlyLookupDst16(de_ctx, io_tctx, p);
    if (dst == NULL || dst->sh == NULL)
        return;
    //printf("IPOnlyMatchPacket processing arrays...\n");

    /* copy the match array from source... */
    uint32_t u;
    for (u = 0; u < io_tctx->sig_match_size; u++) {
        io_tctx->sig_match_array[u] = src->sh->sig_array[u];
    }

    /* ...then bitwise AND it with the dst... */
    for (u = 0; u < io_tctx->sig_match_size; u++) {
        io_tctx->sig_match_array[u] &= dst->sh->sig_array[u];
    }

    //printf("Let's inspect the sigs\n");

    //uint32_t sig_cnt;
    //if (src->sh->sig_cnt > dst->sh->sig_cnt) sig_cnt = dst->sh->sig_cnt;
    //else                                     sig_cnt = src->sh->sig_cnt;

    /* ...the result is that only the sigs with both
     * enable match */
    uint32_t idx;
    for (idx = 0; idx < io_ctx->sig_cnt; idx++) {
        uint32_t sig = io_ctx->match_array[idx];

        //printf("sig internal id %" PRIu32 "\n", sig);

        /* sig doesn't match */
        if (!(io_tctx->sig_match_array[(sig / 8)] & (1<<(sig % 8)))) {
            continue;
        }

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        /* check the protocol */
        if (!(s->proto.proto[(p->proto/8)] & (1<<(p->proto%8))))
            continue;

        /* check the source address */
        if (!(s->flags & SIG_FLAG_SRC_ANY)) {
            DetectAddress *saddr = DetectAddressLookupInHead(&s->src,&p->src);
            if (saddr == NULL)
                continue;
        }
        /* check the destination address */
        if (!(s->flags & SIG_FLAG_DST_ANY)) {
            DetectAddress *daddr = DetectAddressLookupInHead(&s->dst,&p->dst);
            if (daddr == NULL)
                continue;
        }

        if (!(s->flags & SIG_FLAG_NOALERT)) {
            PacketAlertHandle(de_ctx,s,p);
            /* set verdict on packet */
            p->action = s->action;
        }
    }
}

int IPOnlyBuildMatchArray(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    uint32_t idx = 0;
    uint32_t sig = 0;

    //printf("IPOnlyBuildMatchArray: max_idx %" PRIu32 "\n", io_ctx->max_idx);
    for (sig = 0; sig < io_ctx->max_idx + 1; sig++) {
        if (!(io_ctx->sig_init_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        io_ctx->sig_cnt++;
    }
    //printf("IPOnlyBuildMatchArray: sig_cnt %" PRIu32 "\n", io_ctx->sig_cnt);

    io_ctx->match_array = malloc(io_ctx->sig_cnt * sizeof(uint32_t));
    if (io_ctx->match_array == NULL)
        return -1;

    memset(io_ctx->match_array,0, io_ctx->sig_cnt * sizeof(uint32_t));

    for (sig = 0; sig < io_ctx->max_idx + 1; sig++) {
        if (!(io_ctx->sig_init_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        io_ctx->match_array[idx] = s->num;
        idx++;
    }
    //printf("IPOnlyBuildMatchArray: idx %" PRIu32 "\n", idx);

    return 0;
}

void IPOnlyPrepare(DetectEngineCtx *de_ctx) {
    IPOnlyBuildMatchArray(de_ctx, &de_ctx->io_ctx);

    /* source: set sig_cnt */
    HashListTableBucket *hb = HashListTableGetListHead(de_ctx->io_ctx.ht16_src);
    if (hb == NULL)
        return;

    //printf("SRC: ");
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        DetectAddress *gr = (DetectAddress *)HashListTableGetListData(hb);
        if (gr == NULL)
            continue;

        SigGroupHeadSetSigCnt(gr->sh, de_ctx->io_ctx.max_idx);
        SigGroupHeadInitDataFree(gr->sh->init);
        gr->sh->init = NULL;
        //printf(PRIu32 " ", gr->sh->sig_cnt);
    }
    //printf("\n");

    /* destination: set sig_cnt */
    hb = HashListTableGetListHead(de_ctx->io_ctx.ht16_dst);
    if (hb == NULL)
        return;

    //printf("DST: ");
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        DetectAddress *gr = (DetectAddress *)HashListTableGetListData(hb);
        if (gr == NULL)
            continue;

        SigGroupHeadSetSigCnt(gr->sh, de_ctx->io_ctx.max_idx);
        SigGroupHeadInitDataFree(gr->sh->init);
        gr->sh->init = NULL;
        //printf(PRIu32 " ", gr->sh->sig_cnt);
    }
    //printf("\n");
}

void IPOnlyAddSignature(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx, Signature *s) {
    if (!(s->flags & SIG_FLAG_IPONLY))
        return;

    DetectAddress *src = s->src.ipv4_head;
    DetectAddress *dst = s->dst.ipv4_head;

    for ( ; src != NULL; src = src->next) {
        IPOnlyAddSlash16(de_ctx, io_ctx, io_ctx->ht16_src, src, 0, s);
//        IPOnlyAddSlash24(de_ctx, io_ctx, io_ctx->ht24_src, src, 0, s);
    }

    for ( ; dst != NULL; dst = dst->next) {
        IPOnlyAddSlash16(de_ctx, io_ctx, io_ctx->ht16_dst, dst, 1, s);
//        IPOnlyAddSlash24(de_ctx, io_ctx, io_ctx->ht24_dst, dst, 1, s);
    }

    if (s->num > io_ctx->max_idx)
        io_ctx->max_idx = s->num;

    /* enable the sig in the bitarray */
    io_ctx->sig_init_array[(s->num/8)] |= 1<<(s->num%8);
}

#ifdef UNITTESTS
/**
 * \test check that we set a Signature as IPOnly because it has no rule
 *       option appending a SigMatch and no port is fixed
 */

static int IPOnlyTestSig01(void) {
    int result = 0;
    DetectEngineCtx de_ctx;

    memset(&de_ctx, 0, sizeof(DetectEngineCtx));

    de_ctx.flags |= DE_QUIET;

    Signature *s = SigInit(&de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-01 sig is IPOnly \"; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(&de_ctx, s))
        result = 1;
    else
        printf("expected a IPOnly signature: ");

    SigFree(s);
end:
    return result;
}

/**
 * \test check that we dont set a Signature as IPOnly because it has no rule
 *       option appending a SigMatch but a port is fixed
 */

static int IPOnlyTestSig02 (void) {
    int result = 0;
    DetectEngineCtx de_ctx;
    memset (&de_ctx, 0, sizeof(DetectEngineCtx));

    memset(&de_ctx, 0, sizeof(DetectEngineCtx));

    de_ctx.flags |= DE_QUIET;

    Signature *s = SigInit(&de_ctx,"alert tcp any any -> any 80 (msg:\"SigTest40-02 sig is not IPOnly \"; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(!(SignatureIsIPOnly(&de_ctx, s)))
        result=1;
    else
        printf("got a IPOnly signature: ");

    SigFree(s);

end:
    return result;
}

/**
 * \test check that we set dont set a Signature as IPOnly
 *  because it has rule options appending a SigMatch like content, and pcre
 */

static int IPOnlyTestSig03 (void) {
    int result = 1;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    /* combination of pcre and content */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (pcre and content) \"; content:\"php\"; pcre:\"/require(_once)?/i\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (content): ");
        result=0;
    }
    SigFree(s);

    /* content */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (content) \"; content:\"match something\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (content): ");
        result=0;
    }
    SigFree(s);

    /* uricontent */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (uricontent) \"; uricontent:\"match something\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (uricontent): ");
        result=0;
    }
    SigFree(s);

    /* pcre */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (pcre) \"; pcre:\"/e?idps rule[sz]/i\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (pcre): ");
        result=0;
    }
    SigFree(s);

    /* flow */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (flow) \"; flow:to_server; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (flow): ");
        result=0;
    }
    SigFree(s);

    /* dsize */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (dsize) \"; dsize:100; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (dsize): ");
        result=0;
    }
    SigFree(s);

    /* flowbits */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (flowbits) \"; flowbits:unset; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (flowbits): ");
        result=0;
    }
    SigFree(s);

    /* flowvar */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (flowvar) \"; pcre:\"/(?<flow_var>.*)/i\"; flowvar:var,\"str\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (flowvar): ");
        result=0;
    }
    SigFree(s);

    /* pktvar */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (pktvar) \"; pcre:\"/(?<pkt_var>.*)/i\"; pktvar:var,\"str\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (pktvar): ");
        result=0;
    }
    SigFree(s);

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
#endif /* UNITTESTS */

void IPOnlyRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("IPOnlyTestSig01", IPOnlyTestSig01, 1);
    UtRegisterTest("IPOnlyTestSig02", IPOnlyTestSig02, 1);
    UtRegisterTest("IPOnlyTestSig03", IPOnlyTestSig03, 1);
#endif
}

