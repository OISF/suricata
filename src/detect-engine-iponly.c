/* ip only part of the detection engine */

/* TODO: needs a lot of work
 *
 * The dificulty with ip only matching is that we need to support (very large)
 * netblocks as well. So we can't just add every single ip to a hash as that
 * would be consuming to much memory. Thats why I've chosen to have a hash of
 * /16's with a list inside them. If a netblock to add is bigger than a /16, 
 * we split it into /16's.
 */

#include "vips.h"
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

/* build a lookup tree for src, if we have one: save
 * build a lookup tree for dst, if we have one: save
 * compare tree's: if they have one (or more) matching
 * sig, we have a match. */

#define IPONLY_EXTRACT_16(a) ((a)->ip[0] & 0x0000ffff)
//#define IPONLY_EXTRACT_24(a) ((a)->ip[0] & 0x00ffffff)

/* No need to calc a constant every lookup: htonl(65535) */
#define IPONLY_HTONL_65535 4294901760UL

static u_int32_t IPOnlyHashFunc16(HashListTable *ht, void *data, u_int16_t len) {
    DetectAddressGroup *gr = (DetectAddressGroup *) data;

    u_int32_t hash = IPONLY_EXTRACT_16(gr->ad) % ht->array_size;
    return hash;
}

/*
static u_int32_t IPOnlyHashFunc24(HashListTable *ht, void *data, u_int16_t len) {
    DetectAddressGroup *gr = (DetectAddressGroup *) data;

    u_int32_t hash = IPONLY_EXTRACT_24(gr->ad) % ht->array_size;
    return hash;
}
*/

static void IPOnlyAddSlash16(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx, HashListTable *ht, DetectAddressGroup *gr, char direction, Signature *s) {
    u_int32_t high = ntohl(gr->ad->ip2[0]);
    u_int32_t low = ntohl(gr->ad->ip[0]);

    if ((ntohl(gr->ad->ip2[0]) - ntohl(gr->ad->ip[0])) > 65536) {
        //printf("Bigger than a class/16:\n"); DetectAddressDataPrint(gr->ad);

        u_int32_t s16_cnt = 0;

        while (high > low) {
            s16_cnt++;

            DetectAddressGroup *grtmp = DetectAddressGroupInit();
            if (grtmp == NULL) {
                goto error;
            }
            DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
            if (adtmp == NULL) {
                goto error;
            }
            adtmp->ip[0] = htonl(high - 65535);
            adtmp->ip2[0] = htonl(high);
            grtmp->ad = adtmp;
            grtmp->cnt = 1;

            SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);
            //printf("  -=-  "); DetectAddressDataPrint(na);

            DetectAddressGroup *rgr = HashListTableLookup(ht,grtmp,0);
            if (rgr == NULL) {
                SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

                HashListTableAdd(ht,grtmp,0);
                direction ? io_ctx->a_dst_uniq16++ : io_ctx->a_src_uniq16++;
                //printf(" uniq\n");
            } else {
                SigGroupHeadAppendSig(de_ctx, &rgr->sh, s);

                DetectAddressGroupFree(grtmp);
                direction ? io_ctx->a_dst_total16++ : io_ctx->a_src_total16++;
                //printf(" dup\n");
            }

            if (high >= 65536)
                high -= 65536;
            else
                high = 0;
        }
        //printf(" contains %u /16's\n", s16_cnt);

    } else {
        DetectAddressGroup *grtmp = DetectAddressGroupInit();
        if (grtmp == NULL) {
            goto error;
        }
        DetectAddressData *adtmp = DetectAddressDataCopy(gr->ad);
        if (adtmp == NULL) {
            goto error;
        }
        adtmp->ip[0] = IPONLY_EXTRACT_16(gr->ad);
        adtmp->ip2[0] = IPONLY_EXTRACT_16(gr->ad) | IPONLY_HTONL_65535;
        grtmp->ad = adtmp;
        grtmp->cnt = 1;

        //SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

        DetectAddressGroup *rgr = HashListTableLookup(ht,grtmp,0);
        if (rgr == NULL) {
            SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

            HashListTableAdd(ht,grtmp,0);
            direction ? io_ctx->a_dst_uniq16++ : io_ctx->a_src_uniq16++;
        } else {
            SigGroupHeadAppendSig(de_ctx, &rgr->sh, s);

            DetectAddressGroupFree(grtmp);
            direction ? io_ctx->a_dst_total16++ : io_ctx->a_src_total16++;
        }
    }
error:
    return;
}

/*
static void IPOnlyAddSlash24(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx, HashListTable *ht, DetectAddressGroup *gr, char direction, Signature *s) {
    if ((ntohl(gr->ad->ip2[0]) - ntohl(gr->ad->ip[0])) > 256) {
        //printf("Bigger than a class/24:\n"); DetectAddressDataPrint(a);

        u_int32_t high = ntohl(gr->ad->ip2[0]);
        u_int32_t low = ntohl(gr->ad->ip[0]);
        u_int32_t s24_cnt = 0;

        while (high > low) {
            s24_cnt++;

            DetectAddressGroup *grtmp = DetectAddressGroupInit();
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

            DetectAddressGroup *rgr = HashListTableLookup(ht,grtmp,0);
            if (rgr == NULL) {
                HashListTableAdd(ht,grtmp,0);
                direction ? io_ctx->a_dst_uniq24++ : io_ctx->a_src_uniq24++;
                //printf(" uniq\n");
            } else {
                DetectAddressGroupFree(grtmp);
                direction ? io_ctx->a_dst_total24++ : io_ctx->a_src_total24++;
                //printf(" dup\n");
            }

            if (high >= 256)
                high -= 256;
            else
                high = 0;
        }
        //printf(" contains %u /24's\n", s24_cnt);

    } else {
        DetectAddressGroup *rgr = HashListTableLookup(ht,gr,0);
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

static char IPOnlyCompareFunc(void *data1, u_int16_t len1, void *data2, u_int16_t len2) {
    DetectAddressGroup *a1 = (DetectAddressGroup *)data1;
    DetectAddressGroup *a2 = (DetectAddressGroup *)data2;

    //printf("IPOnlyCompareFunc: "); DetectAddressDataPrint(a1->ad);
    //printf(" "); DetectAddressDataPrint(a2->ad); printf("\n");

    if (DetectAddressCmp(a1->ad,a2->ad) != ADDRESS_EQ)
        return 0;

    return 1;
}

/* XXX error checking */
void IPOnlyInit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    io_ctx->ht16_src = HashListTableInit(65536, IPOnlyHashFunc16, IPOnlyCompareFunc, NULL);
    io_ctx->ht16_dst = HashListTableInit(65536, IPOnlyHashFunc16, IPOnlyCompareFunc, NULL);
/*
    io_ctx->ht24_src = HashListTableInit(65536, IPOnlyHashFunc24, IPOnlyCompareFunc, NULL);
    io_ctx->ht24_dst = HashListTableInit(65536, IPOnlyHashFunc24, IPOnlyCompareFunc, NULL);
*/
    io_ctx->sig_init_size = DetectEngineGetMaxSigId(de_ctx) / 8 + 1;
    io_ctx->sig_init_array = malloc(io_ctx->sig_init_size);
    memset(io_ctx->sig_init_array, 0, io_ctx->sig_init_size);
}

/* XXX error checking */
void DetectEngineIPOnlyThreadInit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyThreadCtx *io_tctx) {
    DetectAddressData *sad = DetectAddressDataInit();
    sad->family = AF_INET;
    DetectAddressData *dad = DetectAddressDataInit();
    dad->family = AF_INET;

    io_tctx->src = DetectAddressGroupInit();
    io_tctx->src->ad = sad;
    io_tctx->dst = DetectAddressGroupInit();
    io_tctx->dst->ad = dad;

        /* initialize the signature bitarray */
    io_tctx->sig_match_size = de_ctx->io_ctx.max_idx / 8 + 1;
    io_tctx->sig_match_array = malloc(io_tctx->sig_match_size);
    memset(io_tctx->sig_match_array, 0, io_tctx->sig_match_size);
}

void IPOnlyPrint(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    if (!(de_ctx->flags & DE_QUIET)) {
        printf(" * IP ONLY (SRC): %u /16's in our hash, %u total address ranges in them\n",
                io_ctx->a_src_uniq16, io_ctx->a_src_uniq16 + io_ctx->a_src_total16);
        printf(" * IP ONLY (DST): %u /16's in our hash, %u total address ranges in them\n",
                io_ctx->a_dst_uniq16, io_ctx->a_dst_uniq16 + io_ctx->a_dst_total16);
/*
        printf(" * IP ONLY (SRC): %u /24's in our hash, %u total address ranges in them\n",
                io_ctx->a_src_uniq24, io_ctx->a_src_uniq24 + io_ctx->a_src_total24);
        printf(" * IP ONLY (DST): %u /24's in our hash, %u total address ranges in them\n",
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

DetectAddressGroup *IPOnlyLookupSrc16(DetectEngineCtx *de_ctx, DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p) {
    io_tctx->src->ad->ip[0] = GET_IPV4_SRC_ADDR_U32(p) & 0x0000ffff;
    io_tctx->src->ad->ip2[0] = (GET_IPV4_SRC_ADDR_U32(p) & 0x0000ffff) | IPONLY_HTONL_65535;

    //printf("IPOnlyLookupSrc16: "); DetectAddressDataPrint(io_tctx->src->ad); printf("\n");

    DetectAddressGroup *rgr = HashListTableLookup(de_ctx->io_ctx.ht16_src, io_tctx->src, 0);

    return rgr;
}

DetectAddressGroup *IPOnlyLookupDst16(DetectEngineCtx *de_ctx, DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p) {
    io_tctx->dst->ad->ip[0] = GET_IPV4_DST_ADDR_U32(p) & 0x0000ffff;
    io_tctx->dst->ad->ip2[0] = (GET_IPV4_DST_ADDR_U32(p) & 0x0000ffff) | IPONLY_HTONL_65535;

    //printf("IPOnlyLookupDst16: "); DetectAddressDataPrint(io_tctx->dst->ad); printf("\n");

    DetectAddressGroup *rgr = HashListTableLookup(de_ctx->io_ctx.ht16_dst, io_tctx->dst, 0);

    return rgr;
}

/* XXX handle any case: preinit a array with the any's set to 1 for both
 * src and dst, and use that if src/dst is NULL and AND that with the other
 * array. */
void IPOnlyMatchPacket(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx,
                       DetectEngineIPOnlyThreadCtx *io_tctx, Packet *p) {
    DetectAddressGroup *src = NULL, *dst = NULL;
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
    u_int32_t u;
    for (u = 0; u < io_tctx->sig_match_size; u++) {
        io_tctx->sig_match_array[u] = src->sh->sig_array[u];
    }

    /* ...then bitwise AND it with the dst... */
    for (u = 0; u < io_tctx->sig_match_size; u++) {
        io_tctx->sig_match_array[u] &= dst->sh->sig_array[u];
    }

    //printf("Let's inspect the sigs\n");

    //u_int32_t sig_cnt;
    //if (src->sh->sig_cnt > dst->sh->sig_cnt) sig_cnt = dst->sh->sig_cnt;
    //else                                     sig_cnt = src->sh->sig_cnt;

    /* ...the result is that only the sigs with both
     * enable match */
    u_int32_t idx;
    for (idx = 0; idx < io_ctx->sig_cnt; idx++) {
        u_int32_t sig = io_ctx->match_array[idx];

        //printf("sig internal id %u\n", sig);

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
            DetectAddressGroup *saddr = DetectAddressLookupGroup(&s->src,&p->src);
            if (saddr == NULL)
                continue;
        }
        /* check the destination address */
        if (!(s->flags & SIG_FLAG_DST_ANY)) {
            DetectAddressGroup *daddr = DetectAddressLookupGroup(&s->dst,&p->dst);
            if (daddr == NULL)
                continue;
        }


        if (!(s->flags & SIG_FLAG_NOALERT)) {
            PacketAlertAppend(p, 1, s->id, s->rev, s->prio, s->msg);

            /* set verdict on packet */
            p->action = s->action;
        }
    }
}

int IPOnlyBuildMatchArray(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx) {
    u_int32_t idx = 0;
    u_int32_t sig = 0;

    //printf("IPOnlyBuildMatchArray: max_idx %u\n", io_ctx->max_idx);
    for (sig = 0; sig < io_ctx->max_idx + 1; sig++) {
        if (!(io_ctx->sig_init_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        io_ctx->sig_cnt++;
    }
    //printf("IPOnlyBuildMatchArray: sig_cnt %u\n", io_ctx->sig_cnt);

    io_ctx->match_array = malloc(io_ctx->sig_cnt * sizeof(u_int32_t));
    if (io_ctx->match_array == NULL)
        return -1;

    memset(io_ctx->match_array,0, io_ctx->sig_cnt * sizeof(u_int32_t));

    for (sig = 0; sig < io_ctx->max_idx + 1; sig++) {
        if (!(io_ctx->sig_init_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        io_ctx->match_array[idx] = s->num;
        idx++;
    }
    //printf("IPOnlyBuildMatchArray: idx %u\n", idx);

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
        DetectAddressGroup *gr = (DetectAddressGroup *)HashListTableGetListData(hb);
        if (gr == NULL)
            continue;

        SigGroupHeadSetSigCnt(gr->sh, de_ctx->io_ctx.max_idx);
        //printf("%u ", gr->sh->sig_cnt);
    }
    //printf("\n");

    /* destination: set sig_cnt */
    hb = HashListTableGetListHead(de_ctx->io_ctx.ht16_dst);
    if (hb == NULL)
        return;

    //printf("DST: ");
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        DetectAddressGroup *gr = (DetectAddressGroup *)HashListTableGetListData(hb);
        if (gr == NULL)
            continue;

        SigGroupHeadSetSigCnt(gr->sh, de_ctx->io_ctx.max_idx);
        //printf("%u ", gr->sh->sig_cnt);
    }
    //printf("\n");
}

void IPOnlyAddSignature(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx, Signature *s) {
    if (!(s->flags & SIG_FLAG_IPONLY))
        return;

    DetectAddressGroup *src = s->src.ipv4_head;
    DetectAddressGroup *dst = s->dst.ipv4_head;

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


