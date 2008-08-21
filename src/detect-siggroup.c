
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-address.h"
#include "detect-mpm.h"

int SigGroupHeadCmp(SigGroupHead *, SigGroupHead *);

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

    /* connect the signature to the container */
    sg->s = s;

    /* see if we have a head already */
    if (ag->sh == NULL) {
        ag->sh = malloc(sizeof(SigGroupHead));
        if (ag->sh == NULL) {
            goto error;
        }
        memset(ag->sh, 0, sizeof(SigGroupHead));
    }

    if (ag->sh->head == NULL) {
        /* put it as first in the list */
        ag->sh->head = sg;
    } else {
        /* append to the list */
        tmp_sg = ag->sh->head;
        while (tmp_sg->next != NULL) {
            tmp_sg = tmp_sg->next;
        }

        tmp_sg->next = sg;
    }
    ag->sh->sig_cnt++;
    return 0;
error:
    return -1;
}

/* XXX function name */
int SigGroupClean(DetectAddressGroup *ag) {
    SigGroupContainer *sg = NULL, *next_sg = NULL;

    if (ag->sh == NULL)
        return 0;

    if (!(ag->sh->flags & SIG_GROUP_COPY))
        PatternMatchDestroyGroup(ag->sh);

    sg = ag->sh->head;

    while (sg != NULL) {
        next_sg = sg->next;

        sg->s->rulegroup_refcnt--;
        sg->s = NULL;
        free(sg);

        sg = next_sg;        
    }

    free(ag->sh);
    return 0;
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

