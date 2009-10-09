/* Ports part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * TODO VJ
 * - move this out of the detection plugin structure
 * - more unittesting
 *
 *
 * */

#include "eidps-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-port.h"

#include "util-debug.h"

//#define DEBUG

int DetectPortSetupTmp (DetectEngineCtx *, Signature *s, SigMatch *m, char *sidstr);
void DetectPortTests (void);

void DetectPortRegister (void) {
    sigmatch_table[DETECT_PORT].name = "__port__";
    sigmatch_table[DETECT_PORT].Match = NULL;
    sigmatch_table[DETECT_PORT].Setup = DetectPortSetupTmp;
    sigmatch_table[DETECT_PORT].Free = NULL;
    sigmatch_table[DETECT_PORT].RegisterTests = DetectPortTests;
}

/* prototypes */
static int DetectPortCutNot(DetectPort *, DetectPort **);
static int DetectPortCut(DetectEngineCtx *, DetectPort *, DetectPort *, DetectPort **);
DetectPort *PortParse(char *str);
int DetectPortIsValidRange(char *);

/* memory usage counters */
static uint32_t detect_port_memory = 0;
static uint32_t detect_port_init_cnt = 0;
static uint32_t detect_port_free_cnt = 0;

DetectPort *DetectPortInit(void) {
    DetectPort *dp = malloc(sizeof(DetectPort));
    if (dp == NULL) {
        return NULL;
    }
    memset(dp, 0, sizeof(DetectPort));

    detect_port_memory += sizeof(DetectPort);
    detect_port_init_cnt++;

    return dp;
}

/* free a DetectPort object */
void DetectPortFree(DetectPort *dp) {
    if (dp == NULL)
        return;

    /* only free the head if we have the original */
    if (dp->sh != NULL && !(dp->flags & PORT_SIGGROUPHEAD_COPY)) {
        SigGroupHeadFree(dp->sh);
    }
    dp->sh = NULL;

    if (dp->dst_ph != NULL && !(dp->flags & PORT_GROUP_PORTS_COPY)) {
        DetectPortCleanupList(dp->dst_ph);
    }
    dp->dst_ph = NULL;

    detect_port_memory -= sizeof(DetectPort);
    detect_port_free_cnt++;
    free(dp);
}

void DetectPortPrintMemory(void) {
    printf(" * Port memory stats (DetectPort %" PRIuMAX "):\n", (uintmax_t)sizeof(DetectPort));
    printf("  - detect_port_memory %" PRIu32 "\n", detect_port_memory);
    printf("  - detect_port_init_cnt %" PRIu32 "\n", detect_port_init_cnt);
    printf("  - detect_port_free_cnt %" PRIu32 "\n", detect_port_free_cnt);
    printf("  - outstanding ports %" PRIu32 "\n", detect_port_init_cnt - detect_port_free_cnt);
    printf(" * Port memory stats done\n");
}

/* used to see if the exact same portrange exists in the list
 * returns a ptr to the match, or NULL if no match
 */
DetectPort *DetectPortLookup(DetectPort *head, DetectPort *dp) {
    DetectPort *cur;

    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             if (DetectPortCmp(cur, dp) == PORT_EQ)
                 return cur;
        }
    }

    return NULL;
}

void DetectPortPrintList(DetectPort *head) {
    DetectPort *cur;
    uint16_t cnt = 0;

    printf("list:\n");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             printf("SIGS %6u ", cur->sh ? cur->sh->sig_cnt : 0);

             DetectPortPrint(cur);
             cnt++;
             printf("\n");
        }
    }
    printf("endlist (cnt %" PRIu32 ")\n", cnt);
}

void DetectPortCleanupList (DetectPort *head) {
    if (head == NULL)
        return;

    DetectPort *cur, *next;

    for (cur = head; cur != NULL; ) {
         next = cur->next;

         DetectPortFree(cur);
         cur = next;
    }

    head = NULL;
}

/* do a sorted insert, where the top of the list should be the biggest
 * port range.
 *
 * XXX current sorting only works for overlapping ranges */
int DetectPortAdd(DetectPort **head, DetectPort *dp) {
    DetectPort *cur, *prev_cur = NULL;

    //printf("DetectPortAdd: adding "); DetectPortPrint(ag); printf("\n");

    if (*head != NULL) {
        for (cur = *head; cur != NULL; cur = cur->next) {
            prev_cur = cur;
            int r = DetectPortCmp(dp,cur);
            if (r == PORT_EB) {
                /* insert here */
                dp->prev = cur->prev;
                dp->next = cur;

                cur->prev = dp;
                if (*head == cur) {
                    *head = dp;
                } else {
                    dp->prev->next = dp;
                }
                return 0;
            }
        }
        dp->prev = prev_cur;
        if (prev_cur != NULL)
            prev_cur->next = dp;
    } else {
        *head = dp;
    }

    return 0;
}

int DetectPortInsertCopy(DetectEngineCtx *de_ctx, DetectPort **head, DetectPort *new) {
    DetectPort *copy = DetectPortCopySingle(de_ctx,new);

    //printf("new  (%p): ", new); DetectPortPrint(new);  printf(" "); DbgPrintSigs2(new->sh);
    //printf("copy (%p): ",copy); DetectPortPrint(copy); printf(" "); DbgPrintSigs2(copy->sh);

    if (copy != NULL) {
        //printf("DetectPortInsertCopy: "); DetectPortPrint(copy); printf("\n");
    }

    return DetectPortInsert(de_ctx, head, copy);
}

/** \brief function for inserting a port group object. This also makes sure
 *         SigGroupContainer lists are handled correctly.
 *
 *  \retval -1 error
 *  \retval 0 not inserted, memory of new is freed
 *  \retval 1 inserted
 * */
int DetectPortInsert(DetectEngineCtx *de_ctx, DetectPort **head, DetectPort *new) {
    if (new == NULL)
        return 0;

#ifdef DEBUG
    SCLogDebug("head %p, new %p", head, new);
    SCLogDebug("inserting (sig %" PRIu32 ")", new->sh ? new->sh->sig_cnt : 0);
    if (SCLogDebugEnabled()) {
        DetectPortPrint(new);
        DetectPortPrintList(*head);
    }
#endif

    /* see if it already exists or overlaps with existing ag's */
    if (*head != NULL) {
        DetectPort *cur = NULL;
        int r = 0;

        for (cur = *head; cur != NULL; cur = cur->next) {
            r = DetectPortCmp(new,cur);
            if (r == PORT_ER) {
                SCLogDebug("PORT_ER DetectPortCmp compared:");
                if (SCLogDebugEnabled()) {
                    DetectPortPrint(new);
                    DetectPortPrint(cur);
                }
                goto error;
            }
            /* if so, handle that */
            if (r == PORT_EQ) {
                SCLogDebug("PORT_EQ %p %p", cur, new);
                /* exact overlap/match */
                if (cur != new) {
                    SigGroupHeadCopySigs(de_ctx, new->sh, &cur->sh);
                    cur->cnt += new->cnt;
                    DetectPortFree(new);
                    return 0;
                }
                return 1;
            } else if (r == PORT_GT) {
                SCLogDebug("PORT_GT (cur->next %p)", cur->next);
                /* only add it now if we are bigger than the last
                 * group. Otherwise we'll handle it later. */
                if (cur->next == NULL) {
                    SCLogDebug("adding GT");
                    /* put in the list */
                    new->prev = cur;
                    cur->next = new;
                    return 1;
                } else {
                    //printf("cur->next "); DetectPortPrint(cur->next); printf("\n");
                }
            } else if (r == PORT_LT) {
                SCLogDebug("PORT_LT");

                /* see if we need to insert the ag anywhere */
                /* put in the list */
                if (cur->prev != NULL)
                    cur->prev->next = new;
                new->prev = cur->prev;
                new->next = cur;
                cur->prev = new;

                /* update head if required */
                if (*head == cur) {
                    *head = new;
                }
                return 1;

            /* alright, those were the simple cases,
             * lets handle the more complex ones now */

            } else if (r == PORT_ES) {
                SCLogDebug("PORT_ES");
                DetectPort *c = NULL;
                r = DetectPortCut(de_ctx,cur,new,&c);
                if (r == -1)
                    goto error;

                DetectPortInsert(de_ctx, head, new);
                if (c != NULL) {
                    SCLogDebug("inserting C (%p)",c);
                    if (SCLogDebugEnabled()) {
                        DetectPortPrint(c);
                    }
                    DetectPortInsert(de_ctx, head, c);
                }
                return 1;
            } else if (r == PORT_EB) {
                SCLogDebug("PORT_EB");
                DetectPort *c = NULL;
                r = DetectPortCut(de_ctx,cur,new,&c);
                if (r == -1)
                    goto error;

                DetectPortInsert(de_ctx, head, new);
                if (c != NULL) {
                    SCLogDebug("inserting C");
                    if (SCLogDebugEnabled()) {
                        DetectPortPrint(c);
                    }
                    DetectPortInsert(de_ctx, head, c);
                }
                return 1;
            } else if (r == PORT_LE) {
                SCLogDebug("PORT_LE");
                DetectPort *c = NULL;
                r = DetectPortCut(de_ctx,cur,new,&c);
                if (r == -1)
                    goto error;

                DetectPortInsert(de_ctx, head, new);
                if (c != NULL) {
                    SCLogDebug("inserting C");
                    if (SCLogDebugEnabled()) {
                        DetectPortPrint(c);
                    }
                    DetectPortInsert(de_ctx, head, c);
                }
                return 1;
            } else if (r == PORT_GE) {
                SCLogDebug("PORT_GE");
                DetectPort *c = NULL;
                r = DetectPortCut(de_ctx,cur,new,&c);
                if (r == -1)
                    goto error;

                DetectPortInsert(de_ctx, head, new);
                if (c != NULL) {
                    SCLogDebug("inserting C");
                    if (SCLogDebugEnabled()) {
                        DetectPortPrint(c);
                    }
                    DetectPortInsert(de_ctx, head, c);
                }
                return 1;
            }
        }

    /* head is NULL, so get a group and set head to it */
    } else {
        SCLogDebug("setting new head %p", new);
        *head = new;
    }

    return 1;
error:
    /* XXX */
    return -1;
}

/** \retval 0 ok
  * \retval -1 error */
static int DetectPortCut(DetectEngineCtx *de_ctx, DetectPort *a, DetectPort *b, DetectPort **c) {
    uint32_t a_port1 = a->port;
    uint32_t a_port2 = a->port2;
    uint32_t b_port1 = b->port;
    uint32_t b_port2 = b->port2;
    DetectPort *tmp = NULL;

    /* default to NULL */
    *c = NULL;

    //printf("a (%p): ",a); DetectPortPrint(a); printf(" "); DbgPrintSigs2(a->sh);
    //printf("b (%p): ",b); DetectPortPrint(b); printf(" "); DbgPrintSigs2(b->sh);

    int r = DetectPortCmp(a,b);
    if (r != PORT_ES && r != PORT_EB && r != PORT_LE && r != PORT_GE) {
        printf("DetectPortCut: we shouldn't be here\n");
        goto error;
    }

    /* get a place to temporary put sigs lists */
    tmp = DetectPortInit();
    if (tmp == NULL) {
        goto error;
    }
    memset(tmp, 0, sizeof(DetectPort));

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_port1 <-> b_port1 - 1
     * part b: b_port1 <-> a_port2
     * part c: a_port2 + 1 <-> b_port2
     */
    if (r == PORT_LE) {
#ifdef DBG
        printf("DetectPortCut: cut r == PORT_LE\n");
#endif
        a->port  = a_port1;
        a->port2 = b_port1 - 1;

        b->port  = b_port1;
        b->port2 = a_port2;

        DetectPort *tmp_c;
        tmp_c = DetectPortInit();
        if (tmp_c == NULL) {
            goto error;
        }

        tmp_c->port  = a_port2 + 1;
        tmp_c->port2 = b_port2;
        *c = tmp_c;

        SigGroupHeadCopySigs(de_ctx,b->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh); /* copy old b to a */

        tmp_c->cnt += b->cnt;
        b->cnt += a->cnt; 

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_port1 <-> a_port1 - 1
     * part b: a_port1 <-> b_port2
     * part c: b_port2 + 1 <-> a_port2
     */
    } else if (r == PORT_GE) {
#ifdef DBG
        printf("DetectPortCut: cut r == PORT_GE\n");
#endif
        a->port  = b_port1;
        a->port2 = a_port1 - 1;

        b->port  = a_port1;
        b->port2 = b_port2;

        DetectPort *tmp_c;
        tmp_c = DetectPortInit();
        if (tmp_c == NULL) {
            goto error;
        }

        tmp_c->port  = b_port2 + 1;
        tmp_c->port2 = a_port2;
        *c = tmp_c;

        /* 'a' gets clean and then 'b' sigs
         * 'b' gets clean, then 'a' then 'b' sigs
         * 'c' gets 'a' sigs */
        SigGroupHeadCopySigs(de_ctx,a->sh,&tmp->sh); /* store old a list */
        SigGroupHeadClearSigs(a->sh); /* clean a list */
        SigGroupHeadCopySigs(de_ctx,tmp->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx,b->sh,&a->sh); /* copy old b to a */
        SigGroupHeadCopySigs(de_ctx,tmp->sh,&b->sh); /* prepend old a before b */

        SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

        tmp->cnt += a->cnt;
        a->cnt = 0;
        tmp_c->cnt += tmp->cnt;
        a->cnt += b->cnt;
        b->cnt += tmp->cnt;
        tmp->cnt = 0;

    /* we have 2 or three parts:
     *
     * 2 part: [[abab]bbb] or [bbb[baba]]
     * part a: a_port1 <-> a_port2
     * part b: a_port2 + 1 <-> b_port2
     *
     * part a: b_port1 <-> a_port1 - 1
     * part b: a_port1 <-> a_port2
     *
     * 3 part [bbb[aaa]bbb]
     * becomes[aaa[bbb]ccc]
     *
     * part a: b_port1 <-> a_port1 - 1
     * part b: a_port1 <-> a_port2
     * part c: a_port2 + 1 <-> b_port2
     */
    } else if (r == PORT_ES) {
#ifdef DBG
        printf("DetectPortCut: cut r == PORT_ES\n");
#endif
        if (a_port1 == b_port1) {
#ifdef DBG
            printf("DetectPortCut: 1\n");
#endif
            a->port  = a_port1;
            a->port2 = a_port2;

            b->port   = a_port2 + 1;
            b->port2  = b_port2;

            /* 'b' overlaps 'a' so 'a' needs the 'b' sigs */
            SigGroupHeadCopySigs(de_ctx,b->sh,&a->sh);
            a->cnt += b->cnt;

        } else if (a_port2 == b_port2) {
#ifdef DBG
            printf("DetectPortCut: 2\n");
#endif
            a->port  = b_port1;
            a->port2 = a_port1 - 1;

            b->port  = a_port1;
            b->port2 = a_port2;

            /* 'a' overlaps 'b' so 'b' needs the 'a' sigs */
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            b->cnt += a->cnt;

        } else {
#ifdef DBG
            printf("DetectPortCut: 3\n");
#endif
            a->port  = b_port1;
            a->port2 = a_port1 - 1;

            b->port  = a_port1;
            b->port2 = a_port2;

            DetectPort *tmp_c;
            tmp_c = DetectPortInit();
            if (tmp_c == NULL) {
                goto error;
            }

            tmp_c->port  = a_port2 + 1;
            tmp_c->port2 = b_port2;
            *c = tmp_c;

            /* 'a' gets clean and then 'b' sigs
             * 'b' gets clean, then 'a' then 'b' sigs
             * 'c' gets 'b' sigs */
            SigGroupHeadCopySigs(de_ctx,a->sh,&tmp->sh); /* store old a list */
            SigGroupHeadClearSigs(a->sh); /* clean a list */
            SigGroupHeadCopySigs(de_ctx,b->sh,&tmp_c->sh); /* copy old b to c */
            SigGroupHeadCopySigs(de_ctx,b->sh,&a->sh); /* copy old b to a */
            SigGroupHeadCopySigs(de_ctx,tmp->sh,&b->sh); /* merge old a with b */

            SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

            tmp->cnt += a->cnt;
            a->cnt = 0;
            tmp_c->cnt += b->cnt;
            a->cnt += b->cnt;
            b->cnt += tmp->cnt;
            tmp->cnt = 0;
        }
    /* we have 2 or three parts:
     *
     * 2 part: [[baba]aaa] or [aaa[abab]]
     * part a: b_port1 <-> b_port2
     * part b: b_port2 + 1 <-> a_port2
     *
     * part a: a_port1 <-> b_port1 - 1
     * part b: b_port1 <-> b_port2
     *
     * 3 part [aaa[bbb]aaa]
     * becomes[aaa[bbb]ccc]
     *
     * part a: a_port1 <-> b_port2 - 1
     * part b: b_port1 <-> b_port2
     * part c: b_port2 + 1 <-> a_port2
     */
    } else if (r == PORT_EB) {
#ifdef DBG
        printf("DetectPortCut: cut r == PORT_EB\n");
#endif
        if (a_port1 == b_port1) {
#ifdef DBG
            printf("DetectPortCut: 1\n");
#endif
            a->port  = b_port1;
            a->port2 = b_port2;

            b->port  = b_port2 + 1;
            b->port2 = a_port2;

            /* 'b' overlaps 'a' so 'a' needs the 'b' sigs */
            SigGroupHeadCopySigs(de_ctx,b->sh,&tmp->sh);
            SigGroupHeadClearSigs(b->sh);
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            SigGroupHeadCopySigs(de_ctx,tmp->sh,&a->sh);

            SigGroupHeadClearSigs(tmp->sh);

            tmp->cnt += b->cnt;
            b->cnt = 0;
            b->cnt += a->cnt;
            a->cnt += tmp->cnt;
            tmp->cnt = 0;

            //printf("2a (%p): ",a); DetectPortPrint(a); printf(" "); DbgPrintSigs2(a->sh);
            //printf("2b (%p): ",b); DetectPortPrint(b); printf(" "); DbgPrintSigs2(b->sh);
        } else if (a_port2 == b_port2) {
#ifdef DBG
            printf("DetectPortCut: 2\n");
#endif
            a->port  = a_port1;
            a->port2 = b_port1 - 1;

            b->port  = b_port1;
            b->port2 = b_port2;

            /* 'a' overlaps 'b' so 'b' needs the 'a' sigs */
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);

            b->cnt += a->cnt;

        } else {
#ifdef DBG
            printf("DetectPortCut: 3\n");
#endif
            a->port  = a_port1;
            a->port2 = b_port1 - 1;

            b->port  = b_port1;
            b->port2 = b_port2;

            DetectPort *tmp_c;
            tmp_c = DetectPortInit();
            if (tmp_c == NULL) {
                goto error;
            }

            tmp_c->port  = b_port2 + 1;
            tmp_c->port2 = a_port2;
            *c = tmp_c;

            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            SigGroupHeadCopySigs(de_ctx,a->sh,&tmp_c->sh);

            b->cnt += a->cnt;
            tmp_c->cnt += a->cnt;
        }
    }

    /* XXX free tmp */
    if (tmp != NULL)
        DetectPortFree(tmp);
    return 0;

error:
    /* XXX free tmp */
    if (tmp != NULL)
        DetectPortFree(tmp);
    return -1;
}

/** \retval 0 ok
  * \retval -1 error */
static int DetectPortCutNot(DetectPort *a, DetectPort **b) {
    uint16_t a_port1 = a->port;
    uint16_t a_port2 = a->port2;

    /* default to NULL */
    *b = NULL;

    if (a_port1 != 0x0000 && a_port2 != 0xFFFF) {
        a->port  = 0x0000;
        a->port2 = a_port1 - 1;

        DetectPort *tmp_b;
        tmp_b = DetectPortInit();
        if (tmp_b == NULL) {
            goto error;
        }

        tmp_b->port  = a_port2 + 1;
        tmp_b->port2 = 0xFFFF;
        *b = tmp_b;

    } else if (a_port1 == 0x0000 && a_port2 != 0xFFFF) {
        a->port  = a_port2 + 1;
        a->port2 = 0xFFFF;

    } else if (a_port1 != 0x0000 && a_port2 == 0xFFFF) {
        a->port  = 0x0000;
        a->port2 = a_port1 - 1;
    } else {
        goto error;
    }

    return 0;

error:
    return -1;
}

int DetectPortCmp(DetectPort *a, DetectPort *b) {
    /* check any */
    if (a->flags & PORT_FLAG_ANY && b->flags & PORT_FLAG_ANY)
        return PORT_EQ;
    if (a->flags & PORT_FLAG_ANY && !(b->flags & PORT_FLAG_ANY))
        return PORT_LT;
    if (!(a->flags & PORT_FLAG_ANY) && b->flags & PORT_FLAG_ANY)
        return PORT_GT;

    uint16_t a_port1 = a->port;
    uint16_t a_port2 = a->port2;
    uint16_t b_port1 = b->port;
    uint16_t b_port2 = b->port2;

    /* PORT_EQ */
    if (a_port1 == b_port1 && a_port2 == b_port2) {
        //printf("PORT_EQ\n");
        return PORT_EQ;
    /* PORT_ES */
    } else if (a_port1 >= b_port1 && a_port1 <= b_port2 && a_port2 <= b_port2) {
        //printf("PORT_ES\n");
        return PORT_ES;
    /* PORT_EB */
    } else if (a_port1 <= b_port1 && a_port2 >= b_port2) {
        //printf("PORT_EB\n");
        return PORT_EB;
    } else if (a_port1 < b_port1 && a_port2 < b_port2 && a_port2 >= b_port1) {
        //printf("PORT_LE\n");
        return PORT_LE;
    } else if (a_port1 < b_port1 && a_port2 < b_port2) {
        //printf("PORT_LT\n");
        return PORT_LT;
    } else if (a_port1 > b_port1 && a_port1 <= b_port2 && a_port2 > b_port2) {
        //printf("PORT_GE\n");
        return PORT_GE;
    } else if (a_port1 > b_port2) {
        //printf("PORT_GT\n");
        return PORT_GT;
    } else {
        /* should be unreachable */
        printf("Internal Error: should be unreachable\n");
    }

    return PORT_ER;
}

DetectPort *DetectPortCopy(DetectEngineCtx *de_ctx, DetectPort *src) {
    if (src == NULL)
        return NULL;

    DetectPort *dst = DetectPortInit();
    if (dst == NULL) {
        goto error;
    }

    memcpy(dst, src, sizeof(DetectPort));
    dst->sh = NULL;

    if (src->next != NULL)
        dst->next = DetectPortCopy(de_ctx, src->next);

    return dst;
error:
    return NULL;
}

DetectPort *DetectPortCopySingle(DetectEngineCtx *de_ctx,DetectPort *src) {
    if (src == NULL)
        return NULL;

    DetectPort *dst = DetectPortInit();
    if (dst == NULL) {
        goto error;
    }

    memcpy(dst,src,sizeof(DetectPort));
    dst->sh = NULL;
    dst->next = NULL;
    dst->prev = NULL;

    SigGroupHeadCopySigs(de_ctx,src->sh,&dst->sh);

    return dst;
error:
    return NULL;
}

int DetectPortSetupTmp (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *addressstr)
{
    return 0;
}


int DetectPortMatch (DetectPort *dp, uint16_t port) {
    if (port >= dp->port &&
        port <= dp->port2) {
        return 1;
    }

    return 0;
}

void DetectPortPrint(DetectPort *dp) {
    if (dp == NULL)
        return;

    if (dp->flags & PORT_FLAG_ANY) {
        SCLogDebug("ANY");
    } else {
        SCLogDebug("%" PRIu32 "-%" PRIu32 "", dp->port, dp->port2);
    }
}

/* find the group matching address in a group head */
DetectPort *
DetectPortLookupGroup(DetectPort *dp, uint16_t port) {
    DetectPort *p = dp;

    if (dp == NULL)
        return NULL;

    for ( ; p != NULL; p = p->next) {
        if (DetectPortMatch(p,port) == 1) {
            //printf("DetectPortLookupGroup: match, port %" PRIu32 ", dp ", port);
            //DetectPortPrint(p); printf("\n");
            return p;
        }
    }

    return NULL;
}

int DetectPortJoin(DetectEngineCtx *de_ctx, DetectPort *target, DetectPort *source) {
    if (target == NULL || source == NULL)
        return -1;

    target->cnt += source->cnt;
    SigGroupHeadCopySigs(de_ctx,source->sh,&target->sh);

    if (source->port < target->port)
        target->port = source->port;

    if (source->port2 > target->port2)
        target->port2 = source->port2;

    return -1;
}

/* parsing routines */

static int DetectPortParseInsert(DetectPort **head, DetectPort *new) {
    return DetectPortInsert(NULL, head, new);
}

static int DetectPortParseInsertString(DetectPort **head, char *s) {
    DetectPort *ad = NULL;
    int r = 0;

    SCLogDebug("head %p, *head %p, s %s", head, *head, s);

    /* parse the address */
    ad = PortParse(s);
    if (ad == NULL) {
        printf("PortParse error \"%s\"\n",s);
        goto error;
    }

    /* handle the not case, we apply the negation then insert the part(s) */
    if (ad->flags & PORT_FLAG_NOT) {
        DetectPort *ad2 = NULL;

        if (DetectPortCutNot(ad, &ad2) < 0) {
            goto error;
        }

        /* normally a 'not' will result in two ad's unless the 'not' is on the
         * start or end of the address space(e.g. 0.0.0.0 or 255.255.255.255) */
        if (ad2 != NULL) {
            if (DetectPortParseInsert(head, ad2) < 0) {
                if (ad2 != NULL) free(ad2);
                goto error;
            }
        }
    }

    r = DetectPortParseInsert(head, ad);
    if (r < 0)
        goto error;

    /* if any, insert 0.0.0.0/0 and ::/0 as well */
    if (r == 1 && ad->flags & PORT_FLAG_ANY) {
        ad = PortParse("0:65535");
        if (ad == NULL)
            goto error;

        if (DetectPortParseInsert(head, ad) < 0)
	        goto error;
    }

    return 0;

error:
    printf("DetectPortParseInsertString error\n");
    if (ad != NULL) free(ad);
    return -1;
}

/* XXX error handling */
static int DetectPortParseDo(DetectPort **head, DetectPort **nhead, char *s,
                             int negate) {
    int i, x;
    int o_set = 0, n_set = 0;
    int range = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[1024] = "";

    SCLogDebug("head %p, *head %p", head, *head);

    for (i = 0, x = 0; i < size && x < sizeof(address); i++) {
        address[x] = s[i];
        x++;

        if (s[i] == ':')
            range = 1;

        if (range == 1 && s[i] == '!') {
            printf("Can't have a negated value in a range.\n");
            return -1;
        } else if (!o_set && s[i] == '!') {
            n_set = 1;
            x--;
        } else if (s[i] == '[') {
            if (!o_set) {
                o_set = 1;
                x = 0;
            }
            depth++;
        } else if (s[i] == ']') {
            if (depth == 1) {
                address[x - 1] = '\0';
                SCLogDebug("Parsed port from DetectPortParseDo - %s", address);
                x = 0;

                DetectPortParseDo(head, nhead, address, negate? negate: n_set);
                n_set = 0;
            }
            depth--;
            range = 0;
        } else if (depth == 0 && s[i] == ',') {
            if (o_set == 1) {
                o_set = 0;
            } else {
                address[x - 1] = '\0';
                SCLogDebug("Parsed port from DetectPortParseDo - %s", address);

                if (negate == 0 && n_set == 0) {
                    DetectPortParseInsertString(head, address);
                } else {
                    DetectPortParseInsertString(nhead, address);
                }
                n_set = 0;
            }
            x = 0;
            range = 0;
        } else if (depth == 0 && i == size-1) {
            range = 0;
            address[x] = '\0';
            SCLogDebug("%s", address);

            x = 0;

            if (negate == 0 && n_set == 0) {
                DetectPortParseInsertString(head,address);
            } else {
                DetectPortParseInsertString(nhead,address);
            }
            n_set = 0;
        }
    }

    return 0;
//error:
//    return -1;
}

/** \brief check if the port group list covers the complete
 *         port space.
 *  \retval 0 no
 *  \retval 1 yes
 */
int DetectPortIsCompletePortSpace(DetectPort *p) {
    uint16_t next_port = 0;

    if (p == NULL)
        return 0;

    if (p->port != 0x0000)
        return 0;

    /* if we're ending with 0xFFFF while we know
       we started with 0x0000 it's the complete space */
    if (p->port2 == 0xFFFF)
        return 1;

    next_port = p->port2 + 1;
    p = p->next;

    for ( ; p != NULL; p = p->next) {
        if (p == NULL)
            return 0;

        if (p->port != next_port)
            return 0;

        if (p->port2 == 0xFFFF)
            return 1;

        next_port = p->port2 + 1;
    }

    return 0;
}

/* part of the parsing routine */
int DetectPortParseMergeNotPorts(DetectPort **head, DetectPort **nhead) {
    DetectPort *ad;
    DetectPort *ag, *ag2;
    int r = 0;

    /* check if the full port space is negated */
    if (DetectPortIsCompletePortSpace(*nhead) == 1) {
        goto error;
    }

    /* step 0: if the head list is empty, but the nhead list isn't
     * we have a pure not thingy. In that case we add a 0:65535
     * first. */
    if (*head == NULL && *nhead != NULL) {
        SCLogDebug("inserting 0:65535 into head");
        r = DetectPortParseInsertString(head,"0:65535");
        if (r < 0) {
            goto error;
        }
    }

    /* step 1: insert our ghn members into the gh list */
    for (ag = *nhead; ag != NULL; ag = ag->next) {
        /* work with a copy of the ad so we can easily clean up
         * the ghn group later. */
        ad = DetectPortCopy(NULL, ag);
        if (ad == NULL) {
            goto error;
        }
        r = DetectPortParseInsert(head, ad);
        if (r < 0) {
            goto error;
        }
    }

    /* step 2: pull the address blocks that match our 'not' blocks */
    for (ag = *nhead; ag != NULL; ag = ag->next) {
        SCLogDebug("ag %p", ag);
        DetectPortPrint(ag);

        for (ag2 = *head; ag2 != NULL; ) {
            SCLogDebug("ag2 %p", ag2);
            DetectPortPrint(ag2);

            r = DetectPortCmp(ag, ag2);
            if (r == PORT_EQ || r == PORT_EB) { /* XXX more ??? */
                if (ag2->prev == NULL) {
                    *head = ag2->next;
                } else {
                    ag2->prev->next = ag2->next;
                }

                if (ag2->next != NULL) {
                    ag2->next->prev = ag2->prev;
                }
                /* store the next ptr and remove the group */
                DetectPort *next_ag2 = ag2->next;
                DetectPortFree(ag2);
                ag2 = next_ag2;
            } else {
                ag2 = ag2->next;
            }
        }
    }

    for (ag2 = *head; ag2 != NULL; ag2 = ag2->next) {
        SCLogDebug("ag2 %p", ag2);
        DetectPortPrint(ag2);
    }

    if (*head == NULL) {
        printf("DetectPortParseMergeNotPorts: no ports left after merge\n");
        goto error;
    }

    return 0;
error:
    return -1;
}

int DetectPortParse(DetectPort **head, char *str) {
    int r;

    SCLogDebug("Port string to be parsed - str %s", str);

    /* negate port list */
    DetectPort *nhead = NULL;

    r = DetectPortParseDo(head, &nhead, str,/* start with negate no */0);
    if (r < 0)
        goto error;

    SCLogDebug("head %p %p, nhead %p", head, *head, nhead);

    /* merge the 'not' address groups */
    if (DetectPortParseMergeNotPorts(head, &nhead) < 0)
        goto error;

    /* free the temp negate head */
    DetectPortFree(nhead);
    return 0;

error:
    DetectPortFree(nhead);
    return -1;
}

DetectPort *PortParse(char *str) {
    char *portdup = strdup(str);
    char *port2 = NULL;

    DetectPort *dp = DetectPortInit();
    if (dp == NULL)
        goto error;

    /* XXX better input validation */

    /* we dup so we can put a nul-termination in it later */
    char *port = portdup;

    /* handle the negation case */
    if (port[0] == '!') {
        dp->flags |= PORT_FLAG_NOT;
        port++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((port2 = strchr(port, ':')) != NULL)  {
        /* 80:81 range format */
        port2[0] = '\0';
        port2++;

        if(DetectPortIsValidRange(port))
            dp->port = atoi(port);
        else
            goto error;

        if (strcmp(port2, "") != 0) {
            if (DetectPortIsValidRange(port2))
                dp->port2 = atoi(port2);
            else
                goto error;
        } else {
            dp->port2 = 65535;
        }

        /* a > b is illegal, a == b is ok */
        if (dp->port > dp->port2)
            goto error;
    } else {
        if (strcasecmp(port,"any") == 0) {
            dp->port = 0;
            dp->port2 = 65535;
        } else if(DetectPortIsValidRange(port)){
            dp->port = dp->port2 = atoi(port);
        } else {
            goto error;
        }
    }

    free(portdup);
    return dp;

error:
    if (portdup) free(portdup);
    return NULL;
}

int DetectPortIsValidRange(char *port){
    if(atoi(port) >= 0 && atoi(port) <= 65535)
        return 1;
    else
        return 0;
}

/* end parsing routines */

/* init hashes */
#define PORT_HASH_SIZE 1024

uint32_t DetectPortHashFunc(HashListTable *ht, void *data, uint16_t datalen) {
    DetectPort *p = (DetectPort *)data;
    uint32_t hash = p->port * p->port2;

    return hash % ht->array_size;
}

char DetectPortCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2) {
    DetectPort *p1 = (DetectPort *)data1;
    DetectPort *p2 = (DetectPort *)data2;

    if (p1->port2 == p2->port2 && p1->port == p2->port && p1->flags == p2->flags)
        return 1;

    return 0;
}

/* dp hash */

int DetectPortDpHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->dport_hash_table = HashListTableInit(PORT_HASH_SIZE, DetectPortHashFunc, DetectPortCompareFunc, NULL);
    if (de_ctx->dport_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

void DetectPortDpHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->dport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->dport_hash_table);
    de_ctx->dport_hash_table = NULL;
}

void DetectPortDpHashReset(DetectEngineCtx *de_ctx) {
    DetectPortDpHashFree(de_ctx);
    DetectPortDpHashInit(de_ctx);
}

int DetectPortDpHashAdd(DetectEngineCtx *de_ctx, DetectPort *p) {
    return HashListTableAdd(de_ctx->dport_hash_table, (void *)p, 0);
}

DetectPort *DetectPortDpHashLookup(DetectEngineCtx *de_ctx, DetectPort *p) {
    DetectPort *rp = HashListTableLookup(de_ctx->dport_hash_table, (void *)p, 0);
    return rp;
}

/* sp hash */

int DetectPortSpHashInit(DetectEngineCtx *de_ctx) {
    de_ctx->sport_hash_table = HashListTableInit(PORT_HASH_SIZE, DetectPortHashFunc, DetectPortCompareFunc, NULL);
    if (de_ctx->sport_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

void DetectPortSpHashFree(DetectEngineCtx *de_ctx) {
    if (de_ctx->sport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sport_hash_table);
    de_ctx->sport_hash_table = NULL;
}

void DetectPortSpHashReset(DetectEngineCtx *de_ctx) {
    DetectPortSpHashFree(de_ctx);
    DetectPortSpHashInit(de_ctx);
}

int DetectPortSpHashAdd(DetectEngineCtx *de_ctx, DetectPort *p) {
    return HashListTableAdd(de_ctx->sport_hash_table, (void *)p, 0);
}

DetectPort *DetectPortSpHashLookup(DetectEngineCtx *de_ctx, DetectPort *p) {
    DetectPort *rp = HashListTableLookup(de_ctx->sport_hash_table, (void *)p, 0);
    return rp;
}

/* end init hashes */

/* TESTS */

#ifdef UNITTESTS
int PortTestParse01 (void) {
    DetectPort *dd = NULL;

    int r = DetectPortParse(&dd,"80");
    if (r == 0) {
        DetectPortFree(dd);
        return 1;
    }

    return 0;
}

int PortTestParse02 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"80");
    if (r == 0) {
        r = DetectPortParse(&dd,"22");
        if (r == 0) {
            result = 1;
        }

        DetectPortCleanupList(dd);
        return result;
    }

    return result;
}

int PortTestParse03 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"80:88");
    if (r == 0) {
        r = DetectPortParse(&dd,"85:100");
        if (r == 0) {
            result = 1;
        }

        DetectPortCleanupList(dd);

        return result;
    }

    return result;
}

int PortTestParse04 (void) {
    DetectPort *dd = NULL;

    int r = DetectPortParse(&dd,"!80:81");
    if (r == 0) {
        DetectPortCleanupList(dd);
        return 1;
    }

    return 0;
}

int PortTestParse05 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"!80:81");
    if (r != 0)
        goto end;

    if (dd->next == NULL)
        goto end;

    if (dd->port != 0 || dd->port2 != 79)
        goto end;

    if (dd->next->port != 82 || dd->next->port2 != 65535)
        goto end;

    DetectPortCleanupList(dd);
    result = 1;
end:
    return result;
}

int PortTestParse06 (void) {
    DetectPort *dd = NULL, *copy = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"22");
    if (r != 0)
        goto end;

    r = DetectPortParse(&dd,"80");
    if (r != 0)
        goto end;

    r = DetectPortParse(&dd,"143");
    if (r != 0)
        goto end;

    copy = DetectPortCopy(NULL,dd);
    if (copy == NULL)
        goto end;

    if (DetectPortCmp(dd,copy) != PORT_EQ)
        goto end;

    if (copy->next == NULL)
        goto end;

    if (DetectPortCmp(dd->next,copy->next) != PORT_EQ)
        goto end;

    if (copy->next->next == NULL)
        goto end;

    if (DetectPortCmp(dd->next->next,copy->next->next) != PORT_EQ)
        goto end;

    if (copy->port != 22 || copy->next->port != 80 || copy->next->next->port != 143)
        goto end;

    result = 1;

end:
    DetectPortCleanupList(dd);
    return result;
}

int PortTestParse07 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"!21:902");
    if (r != 0)
        goto end;

    if (dd->next == NULL)
        goto end;

    if (dd->port != 0 || dd->port2 != 20)
        goto end;

    if (dd->next->port != 903 || dd->next->port2 != 65535)
        goto end;

    DetectPortCleanupList(dd);
    result = 1;
end:
    return result;
}

int PortTestParse08 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"[80:!80]");
    if (r == 0)
        goto end;

    DetectPortCleanupList(dd);
    result = 1;
end:
    return result;
}

int PortTestParse09 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"1024:");
    if (r != 0)
        goto end;

    if (dd == NULL)
        goto end;

    if (dd->port != 1024 || dd->port2 != 0xffff)
        goto end;

    DetectPortCleanupList(dd);
    result = 1;
end:
    return result;
}

/** \test Test port that is too big */
int PortTestParse10 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"777777777777777777777777777777777777777777777777777777777");
    if (r != 0) {
        result = 1 ;
        goto end;
    }

    DetectPortFree(dd);

end:
    return result;

}

/** \test Test second port of range being too big */
int PortTestParse11 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"1024:65536");
    if (r != 0) {
        result = 1 ;
        goto end;
    }

    DetectPortFree(dd);

end:
    return result;

}

/** \test Test second port of range being just right */
int PortTestParse12 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"1024:65535");
    if (r != 0) {
        goto end;
    }

    DetectPortFree(dd);

    result = 1 ;
end:
    return result;

}

/** \test Test first port of range being too big */
int PortTestParse13 (void) {
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(&dd,"65536:65535");
    if (r != 0) {
        result = 1 ;
        goto end;
    }

    DetectPortFree(dd);

end:
    return result;

}

#endif /* UNITTESTS */

void DetectPortTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("PortTestParse01", PortTestParse01, 1);
    UtRegisterTest("PortTestParse02", PortTestParse02, 1);
    UtRegisterTest("PortTestParse03", PortTestParse03, 1);
    UtRegisterTest("PortTestParse04", PortTestParse04, 1);
    UtRegisterTest("PortTestParse05", PortTestParse05, 1);
    UtRegisterTest("PortTestParse06", PortTestParse06, 1);
    UtRegisterTest("PortTestParse07", PortTestParse07, 1);
    UtRegisterTest("PortTestParse08", PortTestParse08, 1);
    UtRegisterTest("PortTestParse09", PortTestParse09, 1);
    UtRegisterTest("PortTestParse10", PortTestParse10, 1);
    UtRegisterTest("PortTestParse11", PortTestParse11, 1);
    UtRegisterTest("PortTestParse12", PortTestParse12, 1);
    UtRegisterTest("PortTestParse13", PortTestParse13, 1);
#endif /* UNITTESTS */
}

