
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-address.h"
#include "detect-mpm.h"

int SigGroupHeadCmp(SigGroupHead *, SigGroupHead *);

static u_int32_t detect_siggroup_memory = 0;
static u_int32_t detect_siggroup_append_cnt = 0;
static u_int32_t detect_siggroup_free_cnt = 0;

static u_int32_t detect_siggroup_head_memory = 0;
static u_int32_t detect_siggroup_head_init_cnt = 0;
static u_int32_t detect_siggroup_head_free_cnt = 0;

/* XXX eeewww global! move to DetectionEngineCtx once we have that! */
static SigGroupHead *sgh_list = NULL;

/* return the first SigGroupHead that matches
 * the lookup one. */
SigGroupHead* SigGroupHeadListGet(SigGroupHead *a) {
    SigGroupHead *b = sgh_list;

    for ( ; b != NULL; b = b->next) {
        if (SigGroupHeadCmp(a,b) == 1 && a != b) {
            return b;
        }
    }
    return NULL;
}

void SigGroupHeadFreeMpmArrays(void) {
    SigGroupHead *b = sgh_list;

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

int SigGroupContentCmp(SigGroupContent *a, SigGroupContent *b);

/* return the first SigGroupHead that matches
 * the lookup one. */
SigGroupHead* SigGroupHeadListGetMpm(SigGroupHead *a) {
    SigGroupHead *b = sgh_list;

    for ( ; b != NULL; b = b->next) {
        if (a->content_size != b->content_size)
            continue;

        if (memcmp(a->content_array,b->content_array,a->content_size) == 0)
            return b;
    }
    return NULL;
}

/* return the first SigGroupHead that matches
 * the lookup one. */
SigGroupHead* SigGroupHeadListGetMpmUri(SigGroupHead *a) {
    SigGroupHead *b = sgh_list;

    for ( ; b != NULL; b = b->next) {
        if (a->uri_content_size != b->uri_content_size)
            continue;

        if (memcmp(a->uri_content_array,b->uri_content_array,a->uri_content_size) == 0)
            return b;
    }
    return NULL;
}

/* basically just reset the prt as the list items
 * themselves are removed elsewhere */
void SigGroupHeadListClean(void) {
    sgh_list = NULL;
}

void SigGroupHeadList(void) {
    SigGroupHead *sh;

    printf("SigGroupHeadList: start\n");
    for (sh = sgh_list; sh != NULL; sh = sh->next) {
        printf("%p sig_cnt %u\n", sh, sh->sig_cnt);
    }
    printf("SigGroupHeadList: end\n");
}

/* put this head in the list */
void SigGroupHeadAppend(SigGroupHead *sh) {
    if (sgh_list == NULL) {
        sgh_list = sh;
    } else {
        SigGroupHead *list = sgh_list;

        while (list->next != NULL)
            list = list->next;

        list->next = sh;
    }
}

int SigGroupAppend(DetectAddressGroup *ag, Signature *s) {
    SigGroupContainer *sg = NULL, *tmp_sg = NULL;

    sg = malloc(sizeof(SigGroupContainer));
    if (sg == NULL) {
        goto error;
    }
    memset(sg,0,sizeof(SigGroupContainer));

    detect_siggroup_append_cnt++;
    detect_siggroup_memory += sizeof(SigGroupContainer);

    /* connect the signature to the container */
    sg->s = s;

    /* see if we have a head already */
    if (ag->sh == NULL) {
        ag->sh = malloc(sizeof(SigGroupHead));
        if (ag->sh == NULL) {
            goto error;
        }
        memset(ag->sh, 0, sizeof(SigGroupHead));

        detect_siggroup_head_init_cnt++;
        detect_siggroup_head_memory += sizeof(SigGroupHead);
    }

    if (ag->sh->head == NULL) {
        /* put it as first in the list */
        ag->sh->head = sg;
        ag->sh->tail = sg;
    } else {
        /* append to the list */
        tmp_sg = ag->sh->tail;
        ag->sh->tail = tmp_sg->next = sg;
    }
    ag->sh->sig_cnt++;
    return 0;
error:
    return -1;
}

int SigGroupListClean(SigGroupHead *sh) {
    SigGroupContainer *sg = NULL, *next_sg = NULL;

    if (sh == NULL)
	return 0;

    sg = sh->head;

    while (sg != NULL) {
        detect_siggroup_free_cnt++;
        detect_siggroup_memory -= sizeof(SigGroupContainer);

        next_sg = sg->next;

        sg->s->rulegroup_refcnt--;
        sg->s = NULL;
        free(sg);

        sh->sig_cnt--;

        sg = next_sg;
    }
    sh->head = NULL;
    sh->tail = NULL;

    return 0;
}


int SigGroupListCopyPrepend(DetectAddressGroup *src, DetectAddressGroup *dst) {
    SigGroupContainer *sg = NULL;

    if (src->sh == NULL)
        return 0;

    if (dst->sh == NULL) {
        dst->sh = malloc(sizeof(SigGroupHead));
        if (dst->sh == NULL) {
            goto error;
        }
        memset(dst->sh, 0, sizeof(SigGroupHead));

        detect_siggroup_head_init_cnt++;
        detect_siggroup_head_memory += sizeof(SigGroupHead);
    }

    /* save the head & tail */
    SigGroupContainer *dsthead = dst->sh->head;
    SigGroupContainer *dsttail = dst->sh->tail;
    /* reset dst head */
    dst->sh->head = NULL;
    dst->sh->tail = NULL;
    /* append the sigs into the now cleared dst */
    for (sg = src->sh->head; sg != NULL; sg = sg->next) {
        SigGroupAppend(dst,sg->s);
    }

    dst->sh->tail->next = dsthead;
    dst->sh->tail = dsttail;
    return 0;
error:
    return -1;
}

int SigGroupListCopyAppend(DetectAddressGroup *src, DetectAddressGroup *dst) {
    SigGroupContainer *sg = NULL;

    if (src->sh == NULL)
        return 0;

    if (dst->sh == NULL) {
        dst->sh = malloc(sizeof(SigGroupHead));
        if (dst->sh == NULL) {
            goto error;
        }
        memset(dst->sh, 0, sizeof(SigGroupHead));

        detect_siggroup_head_init_cnt++;
        detect_siggroup_head_memory += sizeof(SigGroupHead);
    }

    for (sg = src->sh->head; sg != NULL; sg = sg->next) {
        SigGroupAppend(dst,sg->s);
    }

    return 0;
error:
    return -1;
}

int SigGroupHeadCmp(SigGroupHead *a, SigGroupHead *b) {
    SigGroupContainer *sg_a = NULL, *sg_b = NULL;

    if (a->sig_cnt != b->sig_cnt)
        return 0;

    for (sg_a = a->head, sg_b = b->head;
         sg_a != NULL && sg_b != NULL;
         sg_a = sg_a->next, sg_b = sg_b->next) {
        if (sg_a->s != sg_b->s)
            return 0;
    }

    return 1;
}

void SigGroupHeadFree(SigGroupHead *sh) {
    if (sh == NULL)
        return;

    PatternMatchDestroyGroup(sh);

    SigGroupListClean(sh);

    free(sh);

    detect_siggroup_head_free_cnt++;
    detect_siggroup_head_memory -= sizeof(SigGroupHead);
}

void DetectSigGroupPrintMemory(void) {
    printf(" * Sig group memory stats (SigGroupContainer %u):\n", sizeof(SigGroupContainer));
    printf("  - detect_siggroup_memory %u\n", detect_siggroup_memory);
    printf("  - detect_siggroup_append_cnt %u\n", detect_siggroup_append_cnt);
    printf("  - detect_siggroup_free_cnt %u\n", detect_siggroup_free_cnt);
    printf("  - outstanding sig containers %u\n", detect_siggroup_append_cnt - detect_siggroup_free_cnt);
    printf(" * Sig group memory stats done\n");
    printf(" * Sig group head memory stats (SigGroupHead %u):\n", sizeof(SigGroupHead));
    printf("  - detect_siggroup_head_memory %u\n", detect_siggroup_head_memory);
    printf("  - detect_siggroup_head_init_cnt %u\n", detect_siggroup_head_init_cnt);
    printf("  - detect_siggroup_head_free_cnt %u\n", detect_siggroup_head_free_cnt);
    printf("  - outstanding sig containers %u\n", detect_siggroup_head_init_cnt - detect_siggroup_head_free_cnt);
    printf(" * Sig group head memory stats done\n");
    printf(" X Total %u\n", detect_siggroup_memory + detect_siggroup_head_memory);
}


/* -1: a is smaller
 *  0: equal
 *  1: a is bigger
 */
int SigGroupContentCmp(SigGroupContent *a, SigGroupContent *b) {

    //printf("a->content->id %u, b->content->id %u\n", a->content->id, b->content->id);
    if (a->content->id < b->content->id)
        return -1;
    else if (a->content->id > b->content->id)
        return 1;

    /* implied equal */
    return 0;
}

/* load all pattern id's into a single bitarray that we can memcmp
 * with other bitarrays. A fast and efficient way of comparing pattern
 * sets. */
int SigGroupContentLoad(SigGroupHead *sgh) {
    SigGroupContainer *sgc = sgh->head;
    Signature *s;
    SigMatch *sm;
    u_int16_t min_depth = 65535;
    u_int16_t min_offset = 65535;

    if (DetectContentMaxId() == 0)
        return 0;

    sgh->content_size = (DetectContentMaxId() / 8) + 1;
    sgh->content_array = malloc(sgh->content_size * sizeof(u_int32_t));
    if (sgh->content_array == NULL)
        return -1;

    memset(sgh->content_array,0, sgh->content_size * sizeof(u_int32_t));

    for ( ; sgc != NULL; sgc = sgc->next) {
        s = sgc->s;
        if (s == NULL)
            continue;

        sm = s->match;
        if (sm == NULL)
            continue;

        for ( ; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;

                sgh->content_array[(co->id/8)] |= 1<<(co->id%8);

                if (co->depth < min_depth) min_depth = co->depth;
                if (co->offset < min_offset) min_offset = co->offset;
            }
        }
    }
    //printf("  * min_depth %u, min_offset %u\n", min_depth, min_offset);
    return 0;
}

int SigGroupListContentClean(SigGroupHead *sh) {
    if (sh == NULL)
	return 0;

    if (sh->content_array != NULL) {
        free(sh->content_array);
        sh->content_array = NULL;
        sh->content_size = 0;
    }
    return 0;
}

/* -1: a is smaller
 *  0: equal
 *  1: a is bigger
 */
int SigGroupUricontentCmp(SigGroupUricontent *a, SigGroupUricontent *b) {
    //printf("a->content->id %u, b->content->id %u\n", a->content->id, b->content->id);

    if (a->content->id < b->content->id)
        return -1;
    else if (a->content->id > b->content->id)
        return 1;

    /* implied equal */
    return 0;
}

int SigGroupUricontentLoad(SigGroupHead *sgh) {
    SigGroupContainer *sgc = sgh->head;
    Signature *s;
    SigMatch *sm;

    if (DetectUricontentMaxId() == 0)
        return 0;

    sgh->uri_content_size = (DetectUricontentMaxId() / 8) + 1;
    sgh->uri_content_array = malloc(sgh->uri_content_size * sizeof(u_int32_t));
    if (sgh->uri_content_array == NULL)
        return -1;

    memset(sgh->uri_content_array,0, sgh->uri_content_size * sizeof(u_int32_t));

    for ( ; sgc != NULL; sgc = sgc->next) {
        s = sgc->s;
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

int SigGroupListUricontentClean(SigGroupHead *sh) {
    if (sh == NULL)
	return 0;

    if (sh->uri_content_array != NULL) {
        free(sh->uri_content_array);
        sh->uri_content_array = NULL;
        sh->uri_content_size = 0;
    }

    return 0;
}

