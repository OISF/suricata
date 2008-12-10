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

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-port.h"

int DetectPortSetupTmp (Signature *s, SigMatch *m, char *sidstr);
void DetectPortTests (void);

void DetectPortRegister (void) {
    sigmatch_table[DETECT_PORT].name = "__port__";
    sigmatch_table[DETECT_PORT].Match = NULL;
    sigmatch_table[DETECT_PORT].Setup = DetectPortSetupTmp;
    sigmatch_table[DETECT_PORT].Free = NULL;
    sigmatch_table[DETECT_PORT].RegisterTests = DetectPortTests;
}

/* prototypes */
void DetectPortPrint(DetectPort *);
int DetectPortCut(DetectPort *, DetectPort *, DetectPort **);
int DetectPortCutNot(DetectPort *, DetectPort **);
int DetectPortCut(DetectPort *, DetectPort *, DetectPort **);
DetectPort *DetectPortCopy(DetectPort *src);
DetectPort *PortParse(char *str);
int DetectPortCmp(DetectPort *, DetectPort *);

/* memory usage counters */
static u_int32_t detect_port_memory = 0;
static u_int32_t detect_port_init_cnt = 0;
static u_int32_t detect_port_free_cnt = 0;

static u_int32_t detect_port_hash_add_cnt = 0;
static u_int32_t detect_port_hash_add_coll_cnt = 0;
static u_int32_t detect_port_hash_lookup_cnt = 0;
static u_int32_t detect_port_hash_lookup_miss_cnt = 0;
static u_int32_t detect_port_hash_lookup_hit_cnt = 0;
static u_int32_t detect_port_hash_lookup_loop_cnt = 0;

DetectPort *DetectPortInit(void) {
    DetectPort *dp = malloc(sizeof(DetectPort));
    if (dp == NULL) {
        return NULL;
    }
    memset(dp,0,sizeof(DetectPort));

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
    printf(" * Port memory stats (DetectPort %u):\n", sizeof(DetectPort));
    printf("  - detect_port_memory %u\n", detect_port_memory);
    printf("  - detect_port_init_cnt %u\n", detect_port_init_cnt);
    printf("  - detect_port_free_cnt %u\n", detect_port_free_cnt);
    printf("  - outstanding ports %u\n", detect_port_init_cnt - detect_port_free_cnt);
    printf(" * Port memory stats done\n");
#if 0
    printf("  x detect_port_hash_add_cnt %u\n", detect_port_hash_add_cnt);
    printf("  x detect_port_hash_add_insert_cnt %u\n", detect_port_hash_add_insert_cnt);
    printf("  x detect_port_hash_add_coll_cnt %u\n", detect_port_hash_add_coll_cnt);
    printf("  x detect_port_hash_lookup_cnt %u\n", detect_port_hash_lookup_cnt);
    printf("  x detect_port_hash_lookup_miss_cnt %u\n", detect_port_hash_lookup_miss_cnt);
    printf("  x detect_port_hash_lookup_hit_cnt %u\n", detect_port_hash_lookup_hit_cnt);
    printf("  x detect_port_hash_lookup_loop_cnt %u\n", detect_port_hash_lookup_loop_cnt);
#endif
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
    u_int16_t cnt = 0;

    printf("list:\n");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             printf("SIGS %6u ", cur->sh ? cur->sh->sig_cnt : 0);

             DetectPortPrint(cur);
             cnt++;
             printf("\n");
        }
    }
    printf("endlist (cnt %u)\n", cnt);
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
        prev_cur->next = dp;
    } else {
        *head = dp;
    }

    return 0;
}

int DetectPortInsertCopy(DetectPort **head, DetectPort *new) {
    DetectPort *copy = DetectPortCopySingle(new);

    //printf("new  (%p): ", new); DetectPortPrint(new);  printf(" "); DbgPrintSigs2(new->sh);
    //printf("copy (%p): ",copy); DetectPortPrint(copy); printf(" "); DbgPrintSigs2(copy->sh);

    if (copy != NULL) {
        //printf("DetectPortInsertCopy: "); DetectPortPrint(copy); printf("\n");
    }

    return DetectPortInsert(head, copy);
}

//#define DBG
/* function for inserting a port group oject. This also makes sure
 * SigGroupContainer lists are handled correctly.
 *
 * returncodes
 * -1: error
 *  0: not inserted, memory of new is freed
 *  1: inserted
 * */
int DetectPortInsert(DetectPort **head, DetectPort *new) {
    if (new == NULL)
        return 0;


#ifdef DBG
    printf("DetectPortInsert: head %p, new %p, new->dp %p\n", head, new, new->dp);
    printf("DetectPortInsert: inserting (sig %u) ", new->sh ? new->sh->sig_cnt : 0); DetectPortPrint(new); printf("\n");
    //DetectPortPrintList(*head);
#endif

    /* see if it already exists or overlaps with existing ag's */
    if (*head != NULL) {
        DetectPort *cur = NULL;
        int r = 0;

        for (cur = *head; cur != NULL; cur = cur->next) {
//            printf("DetectPortInsert: cur %p ",cur); DetectPortPrint(cur); printf("\n");
//            DetectPortPrintList(cur);
//            printf("DetectPortInsert: cur end ========\n");
            r = DetectPortCmp(new,cur);
            if (r == PORT_ER) {
                printf("PORT_ER DetectPortCmp compared:\n");
                DetectPortPrint(new); printf(" vs. ");
                DetectPortPrint(cur); printf("\n");
                goto error;
            }
            /* if so, handle that */
            if (r == PORT_EQ) {
#ifdef DBG
                printf("DetectPortInsert: PORT_EQ %p %p\n", cur, new);
#endif
                /* exact overlap/match */
                if (cur != new) {
                    SigGroupHeadCopySigs(new->sh,&cur->sh);
                    cur->cnt += new->cnt;
                    DetectPortFree(new);
                    return 0;
                }
                return 1;
            } else if (r == PORT_GT) {
#ifdef DBG
                printf("DetectPortInsert: PORT_GT (cur->next %p)\n", cur->next);
#endif
                /* only add it now if we are bigger than the last
                 * group. Otherwise we'll handle it later. */
                if (cur->next == NULL) {
#ifdef DBG
                    printf("DetectPortInsert: adding GT\n");
#endif
                    /* put in the list */
                    new->prev = cur;
                    cur->next = new;
/*
            printf("DetectPortInsert: cur %p ",cur); DetectPortPrint(cur); printf("\n");
            DetectPortPrintList(cur);
            printf("DetectPortInsert: cur end ========\n");
            printf("DetectPortInsert: new %p ",new); DetectPortPrint(new); printf("\n");
            DetectPortPrintList(new);
            printf("DetectPortInsert: new end ========\n");
*/
                    return 1;
                } else {
                    //printf("cur->next "); DetectPortPrint(cur->next); printf("\n");
                }
            } else if (r == PORT_LT) {
#ifdef DBG
                printf("DetectPortInsert: PORT_LT\n");
#endif
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
#ifdef DBG
                printf("DetectPortInsert: PORT_ES\n");
#endif
                DetectPort *c = NULL;
                r = DetectPortCut(cur,new,&c);
                DetectPortInsert(head, new);
                if (c) {
#ifdef DBG
                    printf("DetectPortInsert: inserting C (%p) ",c); DetectPortPrint(c); printf("\n");
#endif
                    DetectPortInsert(head, c);
                }
                return 1;
            } else if (r == PORT_EB) {
#ifdef DBG
                printf("DetectPortInsert: PORT_EB\n");
#endif
                DetectPort *c = NULL;
                r = DetectPortCut(cur,new,&c);
                //printf("DetectPortCut returned %d\n", r);
                DetectPortInsert(head, new);
                if (c) {
#ifdef DBG
                    printf("DetectPortInsert: inserting C "); DetectPortPrint(c); printf("\n");
#endif
                    DetectPortInsert(head, c);
                }
                return 1;
            } else if (r == PORT_LE) {
#ifdef DBG
                printf("DetectPortInsert: PORT_LE\n");
#endif
                DetectPort *c = NULL;
                r = DetectPortCut(cur,new,&c);
                DetectPortInsert(head, new);
                if (c) {
#ifdef DBG
                    printf("DetectPortInsert: inserting C "); DetectPortPrint(c); printf("\n");
#endif
                    DetectPortInsert(head, c);
                }
                return 1;
            } else if (r == PORT_GE) {
#ifdef DBG
                printf("DetectPortInsert: PORT_GE\n");
#endif
                DetectPort *c = NULL;
                r = DetectPortCut(cur,new,&c);
                DetectPortInsert(head, new);
                if (c) {
#ifdef DBG
                    printf("DetectPortInsert: inserting C "); DetectPortPrint(c); printf("\n");
#endif
                    DetectPortInsert(head, c);
                }
                return 1;
            }
        }

    /* head is NULL, so get a group and set head to it */
    } else {
#ifdef DBG
        printf("DetectPortInsert: Setting new head\n");
#endif
        *head = new;
    }

    return 1;
error:
    /* XXX */
    return -1;
}

int DetectPortSetup(DetectPort **head, char *s) {
    DetectPort  *ad = NULL;
    int r = 0;

    /* parse the address */
    ad = PortParse(s);
    if (ad == NULL) {
        printf("PortParse error \"%s\"\n",s);
        goto error;
    }

    /* handle the not case, we apply the negation
     * then insert the part(s) */
    if (ad->flags & PORT_FLAG_NOT) {
        DetectPort *ad2 = NULL;

        if (DetectPortCutNot(ad,&ad2) < 0) {
            goto error;
        }

        /* normally a 'not' will result in two ad's
         * unless the 'not' is on the start or end
         * of the address space (e.g. 0.0.0.0 or
         * 255.255.255.255). */
        if (ad2 != NULL) {
            if (DetectPortInsert(head, ad2) < 0)
                goto error;
        }
    }

    r = DetectPortInsert(head, ad);
    if (r < 0)
        goto error;

    /* if any, insert 0.0.0.0/0 and ::/0 as well */
    if (r == 1 && ad->flags & PORT_FLAG_ANY) {
        ad = PortParse("0:65535");
        if (ad == NULL)
            goto error;

        if (DetectPortInsert(head, ad) < 0)
	        goto error;
    }

    return 0;

error:
    printf("DetectPortSetup error\n");
    /* XXX cleanup */
    return -1;
}

/* XXX error handling */
int DetectPortParse2(DetectPort **head, DetectPort **nhead, char *s,int negate) {
    int i, x;
    int o_set = 0, n_set = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[1024] = "";

    for (i = 0, x = 0; i < size && x < sizeof(address); i++) {
        address[x] = s[i];
        x++;

        if (!o_set && s[i] == '!') {
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
                address[x-1] = '\0';
                x = 0;

                DetectPortParse2(head,nhead,address,negate ? negate : n_set);
                n_set = 0;
            }
            depth--;
        } else if (depth == 0 && s[i] == ',') {
            if (o_set == 1) {
                o_set = 0;
            } else {
                address[x-1] = '\0';

                if (negate == 0 && n_set == 0) {
                    DetectPortSetup(head,address);
                } else {
                    DetectPortSetup(nhead,address);
                }
                n_set = 0;
            }
            x = 0;
        } else if (depth == 0 && i == size-1) {
            address[x] = '\0';
            x = 0;

            if (negate == 0 && n_set == 0) {
                DetectPortSetup(head,address);
            } else {
                DetectPortSetup(nhead,address);
            }
            n_set = 0;
        }
    }

    return 0;
//error:
//    return -1;
}

int DetectPortMergeNot(DetectPort **head, DetectPort **nhead) {
    DetectPort *ad;
    DetectPort *ag, *ag2;
    int r = 0;

    /* step 0: if the head list is empty, but the nhead list isn't
     * we have a pure not thingy. In that case we add a 0:65535
     * first. */
    if (*head == NULL && *nhead != NULL) {
        r = DetectPortSetup(head,"0:65535");
        if (r < 0) {
            goto error;
        }
    }

    /* step 1: insert our ghn members into the gh list */
    for (ag = *nhead; ag != NULL; ag = ag->next) {
        /* work with a copy of the ad so we can easily clean up
         * the ghn group later. */
        ad = DetectPortCopy(ag);
        if (ad == NULL) {
            goto error;
        }
        r = DetectPortInsert(head,ad);
        if (r < 0) {
            goto error;
        }
    }

    /* step 2: pull the address blocks that match our 'not' blocks */
    for (ag = *nhead; ag != NULL; ag = ag->next) {
        for (ag2 = *head; ag2 != NULL; ) {
            r = DetectPortCmp(ag,ag2);
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

    return 0;
error:
    return -1;
}

int DetectPortParse(DetectPort **head, char *str) {
    int r;

    DetectPort *nhead = NULL;

    r = DetectPortParse2(head,&nhead,str,/* start with negate no */0);
    if (r < 0) {
        goto error;
    }

    /* merge the 'not' address groups */
    if (DetectPortMergeNot(head,&nhead) < 0) {
        goto error;
    }

    /* free the temp negate head */
    DetectPortFree(nhead);
    return 0;
error:
    DetectPortFree(nhead);
    return -1;
}

int DetectPortCut(DetectPort *a, DetectPort *b, DetectPort **c) {
    u_int32_t a_port1 = a->port;
    u_int32_t a_port2 = a->port2;
    u_int32_t b_port1 = b->port;
    u_int32_t b_port2 = b->port2;

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
    DetectPort *tmp = NULL;
    tmp = DetectPortInit();
    if (tmp == NULL) {
        goto error;
    }
    memset(tmp,0,sizeof(DetectPort));

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

        SigGroupHeadCopySigs(b->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(a->sh,&b->sh); /* copy old b to a */

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
        SigGroupHeadCopySigs(a->sh,&tmp->sh); /* store old a list */
        SigGroupHeadClearSigs(a->sh); /* clean a list */
        SigGroupHeadCopySigs(tmp->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(b->sh,&a->sh); /* copy old b to a */
        SigGroupHeadCopySigs(tmp->sh,&b->sh); /* prepend old a before b */

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
            SigGroupHeadCopySigs(b->sh,&a->sh);
            a->cnt += b->cnt;

        } else if (a_port2 == b_port2) {
#ifdef DBG
            printf("DetectPortCut: 2\n");
#endif
            a->port  = b_port1;
            a->port2 = a_port1 - 1;

            b->port  = a_port1;
            b->port2 = a_port2;

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupHeadCopySigs(a->sh,&b->sh);
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
            SigGroupHeadCopySigs(a->sh,&tmp->sh); /* store old a list */
            SigGroupHeadClearSigs(a->sh); /* clean a list */
            SigGroupHeadCopySigs(b->sh,&tmp_c->sh); /* copy old b to c */
            SigGroupHeadCopySigs(b->sh,&a->sh); /* copy old b to a */
            SigGroupHeadCopySigs(tmp->sh,&b->sh); /* prepend old a before b */

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

            /* 'b' overlaps 'a' so a needs the 'b' sigs */
            SigGroupHeadCopySigs(b->sh,&tmp->sh);
            SigGroupHeadClearSigs(b->sh);
            SigGroupHeadCopySigs(a->sh,&b->sh);
            SigGroupHeadCopySigs(tmp->sh,&a->sh);

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

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupHeadCopySigs(a->sh,&b->sh);

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

            SigGroupHeadCopySigs(a->sh,&b->sh);
            SigGroupHeadCopySigs(a->sh,&tmp_c->sh);

            b->cnt += a->cnt;
            tmp_c->cnt += a->cnt;
        }
    }

    /* XXX free tmp */
    DetectPortFree(tmp);
    return 0;

error:
    /* XXX free tmp */
    DetectPortFree(tmp);
    return -1;

    return -1;
}

int DetectPortCutNot(DetectPort *a, DetectPort **b) {
    u_int16_t a_port1 = a->port;
    u_int16_t a_port2 = a->port2;

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

    u_int16_t a_port1 = a->port;
    u_int16_t a_port2 = a->port2;
    u_int16_t b_port1 = b->port;
    u_int16_t b_port2 = b->port2;

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

DetectPort *PortParse(char *str) {
    char *portdup = strdup(str);
    char *port2 = NULL;

    DetectPort *dp = DetectPortInit();
    if (dp == NULL)
        goto error;

    /* we dup so we can put a nul-termination in it later */
    char *port = portdup;

    /* handle the negation case */
    if (port[0] == '!') {
        dp->flags |= PORT_FLAG_NOT;
        port++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((port2 = strchr(port, ':')) != NULL)  {
        /* 1.2.3.4-1.2.3.6 range format */
        port[port2 - port] = '\0';
        port2++;
        dp->port  = atoi(port);
        if (strcmp(port2,"") != 0)
            dp->port2 = atoi(port2);
        else
            dp->port2 = 65535;

        /* a>b is illegal, a=b is ok */
        if (dp->port > dp->port2)
            goto error;

    } else {
        if (strcasecmp(port,"any") == 0) {
            dp->port = 0;
            dp->port2 = 65535;
        } else {
            dp->port = dp->port2 = atoi(port);
        }
    }

    free(portdup);
    return dp;

error:
    if (portdup) free(portdup);
    return NULL;
}

DetectPort *DetectPortCopy(DetectPort *src) {
    if (src == NULL)
        return NULL;

    DetectPort *dst = DetectPortInit();
    if (dst == NULL) {
        goto error;
    }

    memcpy(dst,src,sizeof(DetectPort));
    dst->sh = NULL;

    if (src->next != NULL)
        dst->next = DetectPortCopy(src->next);

    return dst;
error:
    return NULL;
}

DetectPort *DetectPortCopySingle(DetectPort *src) {
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

    SigGroupHeadCopySigs(src->sh,&dst->sh);

    return dst;
error:
    return NULL;
}

int DetectPortSetupTmp (Signature *s, SigMatch *m, char *addressstr)
{
    return 0;
}


int DetectPortMatch (DetectPort *dp, u_int16_t port) {
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
        printf("ANY");
    } else {
        printf("%u-%u", dp->port, dp->port2);
    }
}

/* find the group matching address in a group head */
DetectPort *
DetectPortLookupGroup(DetectPort *dp, u_int16_t port) {
    DetectPort *p = dp;

    if (dp == NULL)
        return NULL;

    for ( ; p != NULL; p = p->next) {
        if (DetectPortMatch(p,port) == 1) {
            //printf("DetectPortLookupGroup: match, port %u, dp ", port);
            //DetectPortPrint(p); printf("\n");
            return p;
        }
    }

    return NULL;
}


/* XXX eeewww global! move to DetectionEngineCtx once we have that! */
static DetectPort **port_hash;
static DetectPort *port_list;
#define PORT_HASH_SIZE 1024

/* XXX dynamic size based on number of sigs? */
int DetectPortHashInit(void) {
    port_hash = (DetectPort **)malloc(sizeof(DetectPort *) * PORT_HASH_SIZE);
    if (port_hash == NULL) {
        goto error;
    }
    memset(port_hash,0,sizeof(DetectPort *) * PORT_HASH_SIZE);

    port_list = NULL;

    return 0;
error:
    return -1;
}

void DetectPortHashFree(void) {
    free(port_hash);
    port_hash = NULL;
}

void DetectPortHashReset(void) {
    if (port_hash != NULL) {
        memset(port_hash,0,sizeof(DetectPort *) * PORT_HASH_SIZE);
    }
    port_list = NULL;
}

DetectPort **DetectPortHashGetPtr(void) {
    return port_hash;
}

DetectPort *DetectPortHashGetListPtr(void) {
    return port_list;
}

u_int32_t DetectPortHashGetSize(void) {
    return PORT_HASH_SIZE;
}

static inline u_int32_t DetectPortHash(DetectPort *p) {
    u_int32_t hash = p->port * p->port2;

    return (hash % PORT_HASH_SIZE);
}

int DetectPortHashAdd(DetectPort *p) {
    u_int32_t hash = DetectPortHash(p);

    //printf("DetectPortHashAdd: hash %u\n", hash);
    detect_port_hash_add_cnt++;

    /* list */
    p->next = port_list;
    port_list = p;

    /* easy: no collision */
    if (port_hash[hash] == NULL) {
        port_hash[hash] = p;
        return 0;
    }

    detect_port_hash_add_coll_cnt++;

    /* harder: collision */
    DetectPort *h = port_hash[hash], *ph = NULL;
    for ( ; h != NULL; h = h->hnext) {
#if 0
        if (DetectPortCmp(p,h) == PORT_EB) {
            if (h == port_hash[hash]) {
                p->hnext = h;
                port_hash[hash] = p;
            } else {
                p->hnext = ph->hnext;
                ph->hnext = p;
            }
            detect_port_hash_add_insert_cnt++;
            return 0;
        }
#endif
        ph = h;
    }
    ph->hnext = p;

    return 0;
}

static inline int DetectPortHashCmp(DetectPort *a,DetectPort *b) {
    if (a->port2 == b->port2 && a->port == b->port && a->flags == b->flags)
        return 1;

    return 0;
}

DetectPort *DetectPortHashLookup(DetectPort *p) {
    u_int32_t hash = DetectPortHash(p);

    //printf("DetectPortHashLookup: hash %u\n", hash);
    detect_port_hash_lookup_cnt++;

    /* easy: no sgh at our hash */
    if (port_hash[hash] == NULL) {
        detect_port_hash_lookup_miss_cnt++;
        //printf("DetectPortHashLookup: not found\n");
        return NULL;
    }

    /* see if we have the sgh we're looking for */
    DetectPort *h = port_hash[hash];
    for ( ; h != NULL; h = h->hnext) {
        detect_port_hash_lookup_loop_cnt++;
        if (DetectPortHashCmp(p,h) == 1) {
            //printf("DetectPortHashLookup: found at %p\n", h);
            detect_port_hash_lookup_hit_cnt++;
            return h;
        }
    }

    //printf("DetectPortHashLookup: not found\n");
    return NULL;
}

/* XXX eeewww global! move to DetectionEngineCtx once we have that! */
static DetectPort **sport_hash;
static DetectPort *sport_list;
#define SPORT_HASH_SIZE 1024

/* XXX dynamic size based on number of sigs? */
int DetectPortSpHashInit(void) {
    sport_hash = (DetectPort **)malloc(sizeof(DetectPort *) * SPORT_HASH_SIZE);
    if (sport_hash == NULL) {
        goto error;
    }
    memset(sport_hash,0,sizeof(DetectPort *) * SPORT_HASH_SIZE);

    sport_list = NULL;
    //printf("DetectSPortHashInit: sport_hash %p\n", sport_hash);
    return 0;
error:
    printf("DetectSPortHashInit: error sport_hash %p\n", sport_hash);
    return -1;
}

void DetectPortSpHashFree(void) {
    free(sport_hash);
    sport_hash = NULL;
}

void DetectPortSpHashReset(void) {
    if (sport_hash != NULL) {
        memset(sport_hash,0,sizeof(DetectPort *) * SPORT_HASH_SIZE);
    }
    sport_list = NULL;
}

DetectPort **DetectPortSpHashGetPtr(void) {
    return sport_hash;
}

DetectPort *DetectPortSpHashGetListPtr(void) {
    return sport_list;
}

u_int32_t DetectPortSpHashGetSize(void) {
    return SPORT_HASH_SIZE;
}

static inline u_int32_t DetectPortSpHash(DetectPort *p) {
    u_int32_t hash = p->port * p->port2;

    return (hash % SPORT_HASH_SIZE);
}

int DetectPortSpHashAdd(DetectPort *p) {
    u_int32_t hash = DetectPortSpHash(p);

    //printf("DetectSPortHashAdd: hash %u\n", hash);
    detect_port_hash_add_cnt++;

    /* list */
    p->next = sport_list;
    sport_list = p;

    /* easy: no collision */
    if (sport_hash[hash] == NULL) {
        sport_hash[hash] = p;
        return 0;
    }

    detect_port_hash_add_coll_cnt++;

    /* harder: collision */
    DetectPort *h = sport_hash[hash], *ph = NULL;
    for ( ; h != NULL; h = h->hnext) {
#if 0
        if (DetectPortCmp(p,h) == PORT_EB) {
            if (h == port_hash[hash]) {
                p->hnext = h;
                port_hash[hash] = p;
            } else {
                p->hnext = ph->hnext;
                ph->hnext = p;
            }
            detect_port_hash_add_insert_cnt++;
            return 0;
        }
#endif
        ph = h;
    }
    ph->hnext = p;

    return 0;
}

DetectPort *DetectPortSpHashLookup(DetectPort *p) {
    u_int32_t hash = DetectPortSpHash(p);

    //printf("DetectSPortHashLookup: hash %u, sport_hash %p, size %u port %p\n", hash, sport_hash, SPORT_HASH_SIZE, p);
    detect_port_hash_lookup_cnt++;

    /* easy: no sgh at our hash */
    if (sport_hash[hash] == NULL) {
        detect_port_hash_lookup_miss_cnt++;
        //printf("DetectSPortHashLookup: not found\n");
        return NULL;
    }

    /* see if we have the sgh we're looking for */
    DetectPort *h = sport_hash[hash];
    for ( ; h != NULL; h = h->hnext) {
        detect_port_hash_lookup_loop_cnt++;
        if (DetectPortHashCmp(p,h) == 1) {
            //printf("DetectSPortHashLookup: found at %p\n", h);
            detect_port_hash_lookup_hit_cnt++;
            return h;
        }
    }

    //printf("DetectSPortHashLookup: not found\n");
    return NULL;
}

int DetectPortJoin(DetectPort *target, DetectPort *source) {
    if (target == NULL || source == NULL)
        return -1;

    target->cnt += source->cnt;
    SigGroupHeadCopySigs(source->sh,&target->sh);

    //DetectPort *port = source->port;
    //for ( ; port != NULL; port = port->next) {
    //    DetectPortInsertCopy(&target->port, port);
    //}

    if (source->port < target->port)
        target->port = source->port;

    if (source->port2 > target->port2)
        target->port2 = source->port2;

    return -1;
}

/* TESTS */

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

    copy = DetectPortCopy(dd);
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


void DetectPortTests(void) {
    UtRegisterTest("PortTestParse01", PortTestParse01, 1);
    UtRegisterTest("PortTestParse02", PortTestParse02, 1);
    UtRegisterTest("PortTestParse03", PortTestParse03, 1);
    UtRegisterTest("PortTestParse04", PortTestParse04, 1);
    UtRegisterTest("PortTestParse05", PortTestParse05, 1);
    UtRegisterTest("PortTestParse06", PortTestParse06, 1);
}

