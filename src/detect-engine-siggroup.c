/* sig group
 *
 *
 */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-mpm.h"
#include "detect-engine-siggroup.h"

#include "detect-content.h"
#include "detect-uricontent.h"

#include "util-hash.h"
#include "util-hashlist.h"

/* prototypes */
int SigGroupHeadClearSigs(SigGroupHead *);

static u_int32_t detect_siggroup_head_memory = 0;
static u_int32_t detect_siggroup_head_init_cnt = 0;
static u_int32_t detect_siggroup_head_free_cnt = 0;
static u_int32_t detect_siggroup_sigarray_memory = 0;
static u_int32_t detect_siggroup_sigarray_init_cnt = 0;
static u_int32_t detect_siggroup_sigarray_free_cnt = 0;
static u_int32_t detect_siggroup_matcharray_memory = 0;
static u_int32_t detect_siggroup_matcharray_init_cnt = 0;
static u_int32_t detect_siggroup_matcharray_free_cnt = 0;

/* Free a sgh */
void SigGroupHeadFree(SigGroupHead *sh) {
    if (sh == NULL)
        return;

    PatternMatchDestroyGroup(sh);
    SigGroupHeadClearSigs(sh);

    if (sh->sig_array != NULL) {
        free(sh->sig_array);
        sh->sig_array = NULL;

        detect_siggroup_sigarray_free_cnt++;
        detect_siggroup_sigarray_memory -= sh->sig_size;
    }

    if (sh->content_array != NULL) {
        free(sh->content_array);
        sh->content_array = NULL;
        sh->content_size = 0;
    }

    if (sh->uri_content_array != NULL) {
        free(sh->uri_content_array);
        sh->uri_content_array = NULL;
        sh->uri_content_size = 0;
    }

    if (sh->match_array) {
        detect_siggroup_matcharray_init_cnt--;
        detect_siggroup_matcharray_memory -= (sh->sig_cnt * sizeof(u_int32_t));
        free(sh->match_array);
        sh->match_array = NULL;
    }
    free(sh);

    detect_siggroup_head_free_cnt++;
    detect_siggroup_head_memory -= sizeof(SigGroupHead);
}

/*
 * initialization hashes
 */

/* mpm sgh hash */
u_int32_t SigGroupHeadMpmHashFunc(HashListTable *ht, void *data, u_int16_t datalen) {
    SigGroupHead *sgh = (SigGroupHead *)data;
    u_int32_t hash = 0;

    u_int32_t b;
    for (b = 0; b < sgh->content_size; b+=1) {
        hash += sgh->content_array[b];
    }
    return hash % ht->array_size;
}

char SigGroupHeadMpmCompareFunc(void *data1, u_int16_t len1, void *data2, u_int16_t len2) {
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (sgh1->content_size != sgh2->content_size)
        return 0;

    if (memcmp(sgh1->content_array,sgh2->content_array,sgh1->content_size) != 0)
        return 0;

    return 1;
}

int SigGroupHeadMpmHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->sgh_mpm_hash_table = HashListTableInit(4096, SigGroupHeadMpmHashFunc, SigGroupHeadMpmCompareFunc, NULL);
    if (de_ctx->sgh_mpm_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

int SigGroupHeadMpmHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    return HashListTableAdd(de_ctx->sgh_mpm_hash_table, (void *)sgh, 0);
}

SigGroupHead *SigGroupHeadMpmHashLookup(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_mpm_hash_table, (void *)sgh, 0);
    return rsgh;
}

void SigGroupHeadMpmHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->sgh_mpm_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_mpm_hash_table);
    de_ctx->sgh_mpm_hash_table = NULL;
}

/* mpm uri sgh hash */

u_int32_t SigGroupHeadMpmUriHashFunc(HashListTable *ht, void *data, u_int16_t datalen) {
    SigGroupHead *sgh = (SigGroupHead *)data;
    u_int32_t hash = 0;

    u_int32_t b;
    for (b = 0; b < sgh->uri_content_size; b+=1) {
        hash += sgh->uri_content_array[b];
    }
    return hash % ht->array_size;
}

char SigGroupHeadMpmUriCompareFunc(void *data1, u_int16_t len1, void *data2, u_int16_t len2) {
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (sgh1->uri_content_size != sgh2->uri_content_size)
        return 0;

    if (memcmp(sgh1->uri_content_array,sgh2->uri_content_array,sgh1->uri_content_size) != 0)
        return 0;

    return 1;
}

int SigGroupHeadMpmUriHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->sgh_mpm_uri_hash_table = HashListTableInit(4096, SigGroupHeadMpmUriHashFunc, SigGroupHeadMpmUriCompareFunc, NULL);
    if (de_ctx->sgh_mpm_uri_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

int SigGroupHeadMpmUriHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    return HashListTableAdd(de_ctx->sgh_mpm_uri_hash_table, (void *)sgh, 0);
}

SigGroupHead *SigGroupHeadMpmUriHashLookup(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_mpm_uri_hash_table, (void *)sgh, 0);
    return rsgh;
}

void SigGroupHeadMpmUriHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->sgh_mpm_uri_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_mpm_uri_hash_table);
    de_ctx->sgh_mpm_uri_hash_table = NULL;
}

/* non-port sgh hash */

u_int32_t SigGroupHeadHashFunc(HashListTable *ht, void *data, u_int16_t datalen) {
    SigGroupHead *sgh = (SigGroupHead *)data;
    u_int32_t hash = 0;

    u_int32_t b;
    for (b = 0; b < sgh->sig_size; b+=1) {
        hash += sgh->sig_array[b];
    }
    return hash % ht->array_size;
}

char SigGroupHeadCompareFunc(void *data1, u_int16_t len1, void *data2, u_int16_t len2) {
    SigGroupHead *sgh1 = (SigGroupHead *)data1;
    SigGroupHead *sgh2 = (SigGroupHead *)data2;

    if (sgh1->sig_size != sgh2->sig_size)
        return 0;

    if (memcmp(sgh1->sig_array,sgh2->sig_array,sgh1->sig_size) != 0)
        return 0;

    return 1;
}

/* sgh */

int SigGroupHeadHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->sgh_hash_table = HashListTableInit(4096, SigGroupHeadHashFunc, SigGroupHeadCompareFunc, NULL);
    if (de_ctx->sgh_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

int SigGroupHeadHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    return HashListTableAdd(de_ctx->sgh_hash_table, (void *)sgh, 0);
}

SigGroupHead *SigGroupHeadHashLookup(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_hash_table, (void *)sgh, 0);
    return rsgh;
}

void SigGroupHeadHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->sgh_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_hash_table);
    de_ctx->sgh_hash_table = NULL;
}

/* port based sgh hash */

/* dport */

int SigGroupHeadDPortHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->sgh_dport_hash_table = HashListTableInit(4096, SigGroupHeadHashFunc, SigGroupHeadCompareFunc, NULL);
    if (de_ctx->sgh_dport_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

int SigGroupHeadDPortHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    return HashListTableAdd(de_ctx->sgh_dport_hash_table, (void *)sgh, 0);
}

SigGroupHead *SigGroupHeadDPortHashLookup(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_dport_hash_table, (void *)sgh, 0);
    return rsgh;
}

void SigGroupHeadDPortHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->dport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_dport_hash_table);
    de_ctx->sgh_dport_hash_table = NULL;
}

/* sport */

int SigGroupHeadSPortHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->sgh_sport_hash_table = HashListTableInit(4096, SigGroupHeadHashFunc, SigGroupHeadCompareFunc, NULL);
    if (de_ctx->sgh_sport_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

int SigGroupHeadSPortHashAdd(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    return HashListTableAdd(de_ctx->sgh_sport_hash_table, (void *)sgh, 0);
}

SigGroupHead *SigGroupHeadSPortHashLookup(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    SigGroupHead *rsgh = HashListTableLookup(de_ctx->sgh_sport_hash_table, (void *)sgh, 0);
    return rsgh;
}

void SigGroupHeadSPortHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->sport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sgh_sport_hash_table);
    de_ctx->sgh_sport_hash_table = NULL;
}

/* end hashes */

static void SigGroupHeadFreeSigArraysHash2(DetectEngineCtx *de_ctx, HashListTable *ht) {
    HashListTableBucket *htb = NULL;

    for (htb = HashListTableGetListHead(ht); htb != NULL; htb = HashListTableGetListNext(htb)) {
        SigGroupHead *sgh = (SigGroupHead *)HashListTableGetListData(htb);

        if (sgh->sig_array != NULL) {
            detect_siggroup_sigarray_free_cnt++;
            detect_siggroup_sigarray_memory -= sgh->sig_size;

            free(sgh->sig_array);
            sgh->sig_array = NULL;
            sgh->sig_size = 0;
        }

        if (sgh->content_array != NULL) {
            free(sgh->content_array);
            sgh->content_array = NULL;
            sgh->content_size = 0;
        }

        if (sgh->uri_content_array != NULL) {
            free(sgh->uri_content_array);
            sgh->uri_content_array = NULL;
            sgh->uri_content_size = 0;
        }
    }
}

static void SigGroupHeadFreeSigArraysHash(DetectEngineCtx *de_ctx, HashListTable *ht) {
    HashListTableBucket *htb = NULL;

    for (htb = HashListTableGetListHead(ht); htb != NULL; htb = HashListTableGetListNext(htb)) {
        SigGroupHead *sgh = (SigGroupHead *)HashListTableGetListData(htb);

        if (sgh->sig_array != NULL) {
            detect_siggroup_sigarray_free_cnt++;
            detect_siggroup_sigarray_memory -= sgh->sig_size;

            free(sgh->sig_array);
            sgh->sig_array = NULL;
            sgh->sig_size = 0;
        }
    }
}

/* Free the sigarrays in the sgh's. Those are only
 * used during the init stage. */
void SigGroupHeadFreeSigArrays(DetectEngineCtx *de_ctx) {
    SigGroupHeadFreeSigArraysHash2(de_ctx, de_ctx->sgh_hash_table);

    SigGroupHeadFreeSigArraysHash(de_ctx, de_ctx->sgh_dport_hash_table);
    SigGroupHeadFreeSigArraysHash(de_ctx, de_ctx->sgh_sport_hash_table);
}

/* Free the mpm arrays that are only used during the
 * init stage */
void SigGroupHeadFreeMpmArrays(DetectEngineCtx *de_ctx) {
    HashListTableBucket *htb = NULL;

    for (htb = HashListTableGetListHead(de_ctx->sgh_dport_hash_table); htb != NULL; htb = HashListTableGetListNext(htb)) {
        SigGroupHead *sgh = (SigGroupHead *)HashListTableGetListData(htb);

        if (sgh->content_array != NULL) {
            free(sgh->content_array);
            sgh->content_array = NULL;
            sgh->content_size = 0;
        }

        if (sgh->uri_content_array != NULL) {
            free(sgh->uri_content_array);
            sgh->uri_content_array = NULL;
            sgh->uri_content_size = 0;
        }
    }

    for (htb = HashListTableGetListHead(de_ctx->sgh_sport_hash_table); htb != NULL; htb = HashListTableGetListNext(htb)) {
        SigGroupHead *sgh = (SigGroupHead *)HashListTableGetListData(htb);

        if (sgh->content_array != NULL) {
            free(sgh->content_array);
            sgh->content_array = NULL;
            sgh->content_size = 0;
        }

        if (sgh->uri_content_array != NULL) {
            free(sgh->uri_content_array);
            sgh->uri_content_array = NULL;
            sgh->uri_content_size = 0;
        }
    }
}

int SigGroupHeadAppendSig(DetectEngineCtx *de_ctx, SigGroupHead **sh, Signature *s) {
    if (de_ctx == NULL)
        return 0;

    /* see if we have a head already */
    if (*sh == NULL) {
        *sh = malloc(sizeof(SigGroupHead));
        if (*sh == NULL) {
            goto error;
        }
        memset(*sh, 0, sizeof(SigGroupHead));

        detect_siggroup_head_init_cnt++;
        detect_siggroup_head_memory += sizeof(SigGroupHead);

        /* initialize the signature bitarray */
        (*sh)->sig_size = DetectEngineGetMaxSigId(de_ctx) / 8 + 1;
        (*sh)->sig_array = malloc((*sh)->sig_size);
        if ((*sh)->sig_array == NULL)
            goto error;
        memset((*sh)->sig_array,0,(*sh)->sig_size);

        detect_siggroup_sigarray_init_cnt++;
        detect_siggroup_sigarray_memory += (*sh)->sig_size;
    }

    /* enable the sig in the bitarray */
    (*sh)->sig_array[(s->num/8)] |= 1<<(s->num%8);

    return 0;
error:
    return -1;
}

int SigGroupHeadClearSigs(SigGroupHead *sh) {
    if (sh == NULL)
        return 0;

    if (sh->sig_array != NULL) {
        memset(sh->sig_array,0,sh->sig_size);
        sh->sig_cnt = 0;
    }
    return 0;
}

int SigGroupHeadCopySigs(DetectEngineCtx *de_ctx, SigGroupHead *src, SigGroupHead **dst) {
    if (src == NULL || de_ctx == NULL)
        return 0;

    if (*dst == NULL) {
        *dst = malloc(sizeof(SigGroupHead));
        if (*dst == NULL) {
            goto error;
        }
        memset(*dst, 0, sizeof(SigGroupHead));

        detect_siggroup_head_init_cnt++;
        detect_siggroup_head_memory += sizeof(SigGroupHead);

        (*dst)->sig_size = DetectEngineGetMaxSigId(de_ctx) / 8 + 1;
        (*dst)->sig_array = malloc((*dst)->sig_size);
        if ((*dst)->sig_array == NULL)
            goto error;

        memset((*dst)->sig_array,0,(*dst)->sig_size);

        detect_siggroup_sigarray_init_cnt++;
        detect_siggroup_sigarray_memory += (*dst)->sig_size;
    }

    /* do the copy */
    u_int32_t idx;
    for (idx = 0; idx < src->sig_size; idx++) {
        (*dst)->sig_array[idx] = (*dst)->sig_array[idx] | src->sig_array[idx];
    }

    return 0;
error:
    return -1;
}

void SigGroupHeadSetSigCnt(SigGroupHead *sgh, u_int32_t max_idx) {
    u_int32_t sig;

    for (sig = 0; sig < max_idx+1; sig++) {
        if (sgh->sig_array[(sig/8)] & (1<<(sig%8))) {
            sgh->sig_cnt++;
        }
    }
}

void DetectSigGroupPrintMemory(void) {
    printf(" * Sig group head memory stats (SigGroupHead %u):\n", sizeof(SigGroupHead));
    printf("  - detect_siggroup_head_memory %u\n", detect_siggroup_head_memory);
    printf("  - detect_siggroup_head_init_cnt %u\n", detect_siggroup_head_init_cnt);
    printf("  - detect_siggroup_head_free_cnt %u\n", detect_siggroup_head_free_cnt);
    printf("  - outstanding sig group heads %u\n", detect_siggroup_head_init_cnt - detect_siggroup_head_free_cnt);
    printf(" * Sig group head memory stats done\n");
    printf(" * Sig group sigarray memory stats:\n");
    printf("  - detect_siggroup_sigarray_memory %u\n", detect_siggroup_sigarray_memory);
    printf("  - detect_siggroup_sigarray_init_cnt %u\n", detect_siggroup_sigarray_init_cnt);
    printf("  - detect_siggroup_sigarray_free_cnt %u\n", detect_siggroup_sigarray_free_cnt);
    printf("  - outstanding sig group sigarrays %u\n", detect_siggroup_sigarray_init_cnt - detect_siggroup_sigarray_free_cnt);
    printf(" * Sig group sigarray memory stats done\n");
    printf(" * Sig group matcharray memory stats:\n");
    printf("  - detect_siggroup_matcharray_memory %u\n", detect_siggroup_matcharray_memory);
    printf("  - detect_siggroup_matcharray_init_cnt %u\n", detect_siggroup_matcharray_init_cnt);
    printf("  - detect_siggroup_matcharray_free_cnt %u\n", detect_siggroup_matcharray_free_cnt);
    printf("  - outstanding sig group matcharrays %u\n", detect_siggroup_matcharray_init_cnt - detect_siggroup_matcharray_free_cnt);
    printf(" * Sig group sigarray memory stats done\n");
    printf(" X Total %u\n", detect_siggroup_head_memory + detect_siggroup_sigarray_memory + detect_siggroup_matcharray_memory);
}

void SigGroupHeadPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    printf("SigGroupHeadPrintSigs: ");

    u_int32_t i;
    for (i = 0; i < sgh->sig_size; i++) {
        if (sgh->sig_array[(i/8)] & (1<<(i%8))) {
            printf("%u ", i);
        }
    }

    printf("\n");
}

void SigGroupHeadPrintContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    printf("SigGroupHeadPrintContent: ");

    u_int32_t i;
    for (i = 0; i < DetectContentMaxId(de_ctx); i++) {
        if (sgh->content_array[(i/8)] & (1<<(i%8))) {
            printf("%u ", i);
        }
    }

    printf("\n");
}

void SigGroupHeadPrintContentCnt(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    printf("SigGroupHeadPrintContent: ");

    u_int32_t i, cnt = 0;
    for (i = 0; i < DetectContentMaxId(de_ctx); i++) {
        if (sgh->content_array[(i/8)] & (1<<(i%8))) {
            cnt++;
        }
    }

    printf("cnt %u\n", cnt);
}

/* load all pattern id's into a single bitarray that we can memcmp
 * with other bitarrays. A fast and efficient way of comparing pattern
 * sets. */
int SigGroupHeadLoadContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    if (sgh == NULL)
        return 0;

    Signature *s;
    SigMatch *sm;

    if (DetectContentMaxId(de_ctx) == 0)
        return 0;

    sgh->content_size = (DetectContentMaxId(de_ctx) / 8) + 1;
    sgh->content_array = malloc(sgh->content_size * sizeof(u_int32_t));
    if (sgh->content_array == NULL)
        return -1;

    memset(sgh->content_array,0, sgh->content_size * sizeof(u_int32_t));

    u_int32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        u_int32_t num = sgh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        sm = s->match;
        if (sm == NULL)
            continue;

        for ( ; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;

                sgh->content_array[(co->id/8)] |= 1<<(co->id%8);
            }
        }
    }

    return 0;
}

int SigGroupHeadClearContent(SigGroupHead *sh) {
    if (sh == NULL)
        return 0;

    if (sh->content_array != NULL) {
        free(sh->content_array);
        sh->content_array = NULL;
        sh->content_size = 0;
    }
    return 0;
}

int SigGroupHeadLoadUricontent(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    if (sgh == NULL)
        return 0;

    Signature *s;
    SigMatch *sm;

    if (DetectUricontentMaxId(de_ctx) == 0)
        return 0;

    sgh->uri_content_size = (DetectUricontentMaxId(de_ctx) / 8) + 1;
    sgh->uri_content_array = malloc(sgh->uri_content_size * sizeof(u_int32_t));
    if (sgh->uri_content_array == NULL)
        return -1;

    memset(sgh->uri_content_array,0, sgh->uri_content_size * sizeof(u_int32_t));

    u_int32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        u_int32_t num = sgh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        sm = s->match;
        if (sm == NULL)
            continue;

        for ( ; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT) {
                DetectUricontentData *co = (DetectUricontentData *)sm->ctx;

                sgh->uri_content_array[(co->id/8)] |= 1<<(co->id%8);
            }
        }
    }
    return 0;
}

int SigGroupHeadClearUricontent(SigGroupHead *sh) {
    if (sh == NULL)
	return 0;

    if (sh->uri_content_array != NULL) {
        free(sh->uri_content_array);
        sh->uri_content_array = NULL;
        sh->uri_content_size = 0;
    }

    return 0;
}

/* Create an array with all the internal id's of the sigs
 * that this sig group head will check for. */
int SigGroupHeadBuildMatchArray (DetectEngineCtx *de_ctx, SigGroupHead *sgh, u_int32_t max_idx) {
    u_int32_t idx = 0;
    u_int32_t sig = 0;

    if (sgh == NULL)
        return 0;

/* XXX ugly */
    if (sgh->match_array == NULL)
        free(sgh->match_array);

    sgh->match_array = malloc(sgh->sig_cnt * sizeof(u_int32_t));
    if (sgh->match_array == NULL)
        return -1;

    memset(sgh->match_array,0, sgh->sig_cnt * sizeof(u_int32_t));

    detect_siggroup_matcharray_init_cnt++;
    detect_siggroup_matcharray_memory += (sgh->sig_cnt * sizeof(u_int32_t));

    for (sig = 0; sig < max_idx+1; sig++) {
        if (!(sgh->sig_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        sgh->match_array[idx] = s->num;
        idx++;
    }

    return 0;
}

int SigGroupHeadContainsSigId (DetectEngineCtx *de_ctx, SigGroupHead *sgh, u_int32_t sid) {
    u_int32_t sig = 0;

    if (sgh == NULL)
        return 0;

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        if (!(sgh->sig_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        if (s->id == sid)
            return 1;
    }

    return 0;
}
