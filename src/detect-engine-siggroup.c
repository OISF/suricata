
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-engine-address.h"
#include "detect-engine-mpm.h"

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

        detect_siggroup_sigarray_free_cnt++;
        detect_siggroup_sigarray_memory -= sh->sig_size;
    }

    free(sh);

    detect_siggroup_head_free_cnt++;
    detect_siggroup_head_memory -= sizeof(SigGroupHead);
}

static int SigGroupHeadCmpSigArray(SigGroupHead *a, SigGroupHead *b) {
    if (a->sig_size != b->sig_size)
        return 0;

    if (memcmp(a->sig_array,b->sig_array,a->sig_size) != 0)
        return 0;

    return 1;
}

/* hashes */

/* XXX eeewww global! move to DetectionEngineCtx once we have that! */
static SigGroupHead **sgh_port_hash;
static SigGroupHead **sgh_hash;
static SigGroupHead **sgh_mpm_hash;
static SigGroupHead **sgh_mpm_uri_hash;

#define HASH_SIZE 65536

/* mpm sgh hash */

/* XXX dynamic size based on number of sigs? */
int SigGroupHeadMpmHashInit(void) {
    sgh_mpm_hash = (SigGroupHead **)malloc(sizeof(SigGroupHead *) * HASH_SIZE);
    if (sgh_mpm_hash == NULL) {
        goto error;
    }
    memset(sgh_mpm_hash,0,sizeof(SigGroupHead *) * HASH_SIZE);

    return 0;
error:
    return -1;
}

u_int32_t SigGroupHeadMpmHash(SigGroupHead *sgh) {
    u_int32_t hash = sgh->content_size<<8;

    u_int32_t b;
    for (b = 0; b < sgh->content_size; b+=1) {
        hash += sgh->content_array[b];
    }

    return (hash % HASH_SIZE);
}

int SigGroupHeadMpmHashAdd(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadMpmHash(sgh);

    //printf("SigGroupHeadMpmHashAdd: hash %u\n", hash);

    /* easy: no collision */
    if (sgh_mpm_hash[hash] == NULL) {
        sgh_mpm_hash[hash] = sgh;
        return 0;
    }

    /* harder: collision */
    SigGroupHead *h = sgh_mpm_hash[hash], *ph = NULL;
    for ( ; h != NULL; h = h->mpm_next) {
        ph = h;
    }
    ph->mpm_next = sgh;

    return 0;
}

SigGroupHead *SigGroupHeadMpmHashLookup(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadMpmHash(sgh);

    //printf("SigGroupHeadMpmHashLookup: hash %u\n", hash);

    /* easy: no sgh at our hash */
    if (sgh_mpm_hash[hash] == NULL) {
        return NULL;
    }

    /* see if we have the sgh we're looking for */
    SigGroupHead *h = sgh_mpm_hash[hash];
    for ( ; h != NULL; h = h->mpm_next) {
        if (sgh->content_size == h->content_size &&
            memcmp(sgh->content_array,h->content_array,sgh->content_size) == 0) {
            return h;
        }
    }

    return NULL;
}

void SigGroupHeadMpmHashFree(void) {
    free(sgh_mpm_hash);
    sgh_mpm_hash = NULL;
}

/* mpm uri sgh hash */

/* XXX dynamic size based on number of sigs? */
int SigGroupHeadMpmUriHashInit(void) {
    sgh_mpm_uri_hash = (SigGroupHead **)malloc(sizeof(SigGroupHead *) * HASH_SIZE);
    if (sgh_mpm_uri_hash == NULL) {
        goto error;
    }
    memset(sgh_mpm_uri_hash,0,sizeof(SigGroupHead *) * HASH_SIZE);

    return 0;
error:
    return -1;
}

u_int32_t SigGroupHeadMpmUriHash(SigGroupHead *sgh) {
    u_int32_t hash = sgh->uri_content_size<<8;

    u_int32_t b;
    for (b = 0; b < sgh->uri_content_size; b+=1) {
        hash += sgh->uri_content_array[b];
    }

    return (hash % HASH_SIZE);
}

int SigGroupHeadMpmUriHashAdd(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadMpmUriHash(sgh);

    //printf("SigGroupHeadHashAdd: hash %u\n", hash);

    /* easy: no collision */
    if (sgh_mpm_uri_hash[hash] == NULL) {
        sgh_mpm_uri_hash[hash] = sgh;
        return 0;
    }

    /* harder: collision */
    SigGroupHead *h = sgh_mpm_uri_hash[hash], *ph = NULL;
    for ( ; h != NULL; h = h->mpm_uri_next) {
        ph = h;
    }
    ph->mpm_uri_next = sgh;

    return 0;
}

SigGroupHead *SigGroupHeadMpmUriHashLookup(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadMpmUriHash(sgh);

    //printf("SigGroupHeadHashLookup: hash %u\n", hash);

    /* easy: no sgh at our hash */
    if (sgh_mpm_uri_hash[hash] == NULL) {
        return NULL;
    }

    /* see if we have the sgh we're looking for */
    SigGroupHead *h = sgh_mpm_uri_hash[hash];
    for ( ; h != NULL; h = h->mpm_uri_next) {
        if (sgh->uri_content_size == h->uri_content_size &&
            memcmp(sgh->uri_content_array,h->uri_content_array,sgh->uri_content_size) == 0) {
            return h;
        }
    }

    return NULL;
}

void SigGroupHeadMpmUriHashFree(void) {
    free(sgh_mpm_uri_hash);
    sgh_mpm_uri_hash = NULL;
}

/* non-port sgh hash */

/* XXX dynamic size based on number of sigs? */
int SigGroupHeadHashInit(void) {
    sgh_hash = (SigGroupHead **)malloc(sizeof(SigGroupHead *) * HASH_SIZE);
    if (sgh_hash == NULL) {
        goto error;
    }
    memset(sgh_hash,0,sizeof(SigGroupHead *) * HASH_SIZE);

    return 0;
error:
    return -1;
}

u_int32_t SigGroupHeadHash(SigGroupHead *sgh) {
    u_int32_t hash = 0;

    u_int32_t b;
    for (b = 0; b < sgh->content_size; b+=1) {
        hash += sgh->content_array[b];
    }

    return (hash % HASH_SIZE);
}

int SigGroupHeadHashAdd(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadHash(sgh);

    //printf("SigGroupHeadHashAdd: hash %u\n", hash);

    /* easy: no collision */
    if (sgh_hash[hash] == NULL) {
        sgh_hash[hash] = sgh;
        return 0;
    }

    /* harder: collision */
    SigGroupHead *h = sgh_hash[hash], *ph = NULL;
    for ( ; h != NULL; h = h->next) {
        ph = h;
    }
    ph->next = sgh;

    return 0;
}

SigGroupHead *SigGroupHeadHashLookup(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadHash(sgh);

    //printf("SigGroupHeadHashLookup: hash %u\n", hash);

    /* easy: no sgh at our hash */
    if (sgh_hash[hash] == NULL) {
        return NULL;
    }

    /* see if we have the sgh we're looking for */
    SigGroupHead *h = sgh_hash[hash];
    for ( ; h != NULL; h = h->next) {
        if (SigGroupHeadCmpSigArray(sgh,h) == 1) {
            return h;
        }
    }

    return NULL;
}

void SigGroupHeadHashFree(void) {
    free(sgh_hash);
    sgh_hash = NULL;
}


/* port based sgh hash */

/* XXX dynamic size based on number of sigs? */
int SigGroupHeadPortHashInit(void) {
    sgh_port_hash = (SigGroupHead **)malloc(sizeof(SigGroupHead *) * HASH_SIZE);
    if (sgh_port_hash == NULL) {
        goto error;
    }
    memset(sgh_port_hash,0,sizeof(SigGroupHead *) * HASH_SIZE);

    return 0;
error:
    return -1;
}

int SigGroupHeadPortHashAdd(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadHash(sgh);

    //printf("SigGroupHeadHashAdd: hash %u\n", hash);

    /* easy: no collision */
    if (sgh_port_hash[hash] == NULL) {
        sgh_port_hash[hash] = sgh;
        return 0;
    }

    /* harder: collision */
    SigGroupHead *h = sgh_port_hash[hash], *ph = NULL;
    for ( ; h != NULL; h = h->next) {
        ph = h;
    }
    ph->next = sgh;

    return 0;
}

SigGroupHead *SigGroupHeadPortHashLookup(SigGroupHead *sgh) {
    u_int32_t hash = SigGroupHeadHash(sgh);

    //printf("SigGroupHeadHashLookup: hash %u\n", hash);

    /* easy: no sgh at our hash */
    if (sgh_port_hash[hash] == NULL) {
        return NULL;
    }

    /* see if we have the sgh we're looking for */
    SigGroupHead *h = sgh_port_hash[hash];
    for ( ; h != NULL; h = h->next) {
        if (SigGroupHeadCmpSigArray(sgh,h) == 1) {
            return h;
        }
    }

    return NULL;
}

void SigGroupHeadPortHashFree(void) {
    free(sgh_port_hash);
    sgh_port_hash = NULL;
}

/* end hashes */

void SigGroupHeadFreeHeads(void) {
    SigGroupHead *b, *nb, *pb;

    u_int32_t hash = 0;
    for ( ; hash < HASH_SIZE; hash++) {
        b = sgh_hash[hash];
        for ( ; b != NULL; ) {
            nb = b->next;

            if (b->flags & SIG_GROUP_HEAD_FREE) {
printf("SigGroupHeadFreeHeads: want to free %p\n", b);
//#if 0
                SigGroupHeadFree(b);

                /* remove from the hash as well */
                if (b == sgh_hash[hash]) {
                    sgh_hash[hash] = nb;
                } else {
                    pb->next = nb;
                }
//#endif
            }

            pb = b;
            b = nb;
        }
    }
}

/* Free the sigarrays in the sgh's. Those are only
 * used during the init stage. */
void SigGroupHeadFreeSigArrays(void) {
    SigGroupHead *b;

    u_int32_t hash = 0;
    for ( ; hash < HASH_SIZE; hash++) {
        b = sgh_hash[hash];
        for ( ; b != NULL; b = b->next) {
            if (b->sig_array != NULL) {
                detect_siggroup_sigarray_free_cnt++;
                detect_siggroup_sigarray_memory -= b->sig_size;

                free(b->sig_array);
                b->sig_array = NULL;
                b->sig_size = 0;
            }
        }
        b = sgh_port_hash[hash];
        for ( ; b != NULL; b = b->next) {
            if (b->sig_array != NULL) {
                detect_siggroup_sigarray_free_cnt++;
                detect_siggroup_sigarray_memory -= b->sig_size;

                free(b->sig_array);
                b->sig_array = NULL;
                b->sig_size = 0;
            }
        }
    }
}

/* Free the mpm arrays that are only used during the
 * init stage */
void SigGroupHeadFreeMpmArrays(void) {
    SigGroupHead *b;

    u_int32_t hash = 0;
    for ( ; hash < HASH_SIZE; hash++) {
        b = sgh_hash[hash];
        for ( ; b != NULL; b = b->next) {
            if (b->content_array != NULL) {
                free(b->content_array);
                b->content_array = NULL;
                b->content_size = 0;
            }
            if (b->uri_content_array != NULL) {
                free(b->uri_content_array);
                b->uri_content_array = NULL;
                b->uri_content_size = 0;
            }
        }
        b = sgh_port_hash[hash];
        for ( ; b != NULL; b = b->next) {
            if (b->content_array != NULL) {
                free(b->content_array);
                b->content_array = NULL;
                b->content_size = 0;
            }
            if (b->uri_content_array != NULL) {
                free(b->uri_content_array);
                b->uri_content_array = NULL;
                b->uri_content_size = 0;
            }
        }
    }
}

int SigGroupHeadAppendSig(SigGroupHead **sh, Signature *s) {
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
        (*sh)->sig_size = SigGetMaxId() / 8 + 1;
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

int SigGroupHeadCopySigs(SigGroupHead *src, SigGroupHead **dst) {
    if (src == NULL)
        return 0;

    if (*dst == NULL) {
        *dst = malloc(sizeof(SigGroupHead));
        if (*dst == NULL) {
            goto error;
        }
        memset(*dst, 0, sizeof(SigGroupHead));

        detect_siggroup_head_init_cnt++;
        detect_siggroup_head_memory += sizeof(SigGroupHead);

        (*dst)->sig_size = SigGetMaxId() / 8 + 1;
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

void SigGroupHeadPrintContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    printf("SigGroupHeadPrintContent: ");

    u_int32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        u_int32_t num = sgh->match_array[sig];

        Signature *s = de_ctx->sig_array[num];
        printf("%u ", s->id);
    }
    printf("\n");
}

/* load all pattern id's into a single bitarray that we can memcmp
 * with other bitarrays. A fast and efficient way of comparing pattern
 * sets. */
int SigGroupHeadLoadContent(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    if (sgh == NULL)
        return 0;

    Signature *s;
    SigMatch *sm;

    if (DetectContentMaxId() == 0)
        return 0;

    sgh->content_size = (DetectContentMaxId() / 8) + 1;
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

    if (DetectUricontentMaxId() == 0)
        return 0;

    sgh->uri_content_size = (DetectUricontentMaxId() / 8) + 1;
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

int SigGroupHeadBuildMatchArray (DetectEngineCtx *de_ctx, SigGroupHead *sgh, u_int32_t max_idx) {
    u_int32_t idx = 0;
    u_int32_t sig = 0;

    if (sgh == NULL)
        return 0;

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

