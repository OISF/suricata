/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Ports part of the detection engine.
 *
 * \todo move this out of the detection plugin structure
 * \todo more unittesting
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-rule-vars.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-port.h"

#include "conf.h"
#include "util-debug.h"
#include "util-error.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

static int DetectPortCutNot(DetectPort *, DetectPort **);
static int DetectPortCut(DetectEngineCtx *, DetectPort *, DetectPort *,
                         DetectPort **);
DetectPort *PortParse(char *str);
int DetectPortIsValidRange(char *);

/** Memory usage counters */
static uint32_t detect_port_memory = 0;
static uint32_t detect_port_init_cnt = 0;
static uint32_t detect_port_free_cnt = 0;

/**
 * \brief Alloc a DetectPort structure and update counters
 *
 * \retval sgh Pointer to the newly created DetectPort on success; or NULL in
 *             case of error.
 */
DetectPort *DetectPortInit(void)
{
    DetectPort *dp = SCMalloc(sizeof(DetectPort));
    if (unlikely(dp == NULL))
        return NULL;
    memset(dp, 0, sizeof(DetectPort));

    detect_port_memory += sizeof(DetectPort);
    detect_port_init_cnt++;

    return dp;
}

/**
 * \brief Free a DetectPort and its members
 *
 * \param dp Pointer to the DetectPort that has to be freed.
 */
void DetectPortFree(DetectPort *dp)
{
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

    //BUG_ON(dp->next != NULL);

    detect_port_memory -= sizeof(DetectPort);
    detect_port_free_cnt++;
    SCFree(dp);
}

/**
 * \brief Prints Memory statistics of the counters at detect-engine-port.[c,h]
 */
void DetectPortPrintMemory(void)
{
    SCLogDebug(" * Port memory stats (DetectPort %" PRIuMAX "):",
               (uintmax_t)sizeof(DetectPort));
    SCLogDebug("  - detect_port_memory %" PRIu32 "", detect_port_memory);
    SCLogDebug("  - detect_port_init_cnt %" PRIu32 "", detect_port_init_cnt);
    SCLogDebug("  - detect_port_free_cnt %" PRIu32 "", detect_port_free_cnt);
    SCLogDebug("  - outstanding ports %" PRIu32 "",
               detect_port_init_cnt - detect_port_free_cnt);
    SCLogDebug(" * Port memory stats done");
}

/**
 * \brief Used to see if the exact same portrange exists in the list
 *
 * \param head Pointer to the DetectPort list head
 * \param dp DetectPort to search in the DetectPort list
 *
 * \retval returns a ptr to the match, or NULL if no match
 */
DetectPort *DetectPortLookup(DetectPort *head, DetectPort *dp)
{
    DetectPort *cur;

    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             if (DetectPortCmp(cur, dp) == PORT_EQ)
                 return cur;
        }
    }

    return NULL;
}

/**
 * \brief Helper function used to print the list of ports
 *        present in this DetectPort list.
 *
 * \param head Pointer to the DetectPort list head
 */
void DetectPortPrintList(DetectPort *head)
{
    DetectPort *cur;
    uint16_t cnt = 0;

    SCLogDebug("= list start:");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             DetectPortPrint(cur);
             cnt++;
        }
        SCLogDebug(" ");
    }
    SCLogDebug("= list end (cnt %" PRIu32 ")", cnt);
}

/**
 * \brief Free a DetectPort list and each of its members
 *
 * \param head Pointer to the DetectPort list head
 */
void DetectPortCleanupList (DetectPort *head)
{
    if (head == NULL)
        return;

    DetectPort *cur, *next;

    for (cur = head; cur != NULL; ) {
        next = cur->next;
        cur->next = NULL;
        DetectPortFree(cur);
        cur = next;
    }
}

/**
 * \brief Do a sorted insert, where the top of the list should be the biggest
 * port range.
 *
 * \todo XXX current sorting only works for overlapping ranges
 *
 * \param head Pointer to the DetectPort list head
 * \param dp Pointer to DetectPort to search in the DetectPort list
 * \retval 0 if dp is added correctly
 */
int DetectPortAdd(DetectPort **head, DetectPort *dp)
{
    DetectPort *cur, *prev_cur = NULL;

    //SCLogDebug("DetectPortAdd: adding "); DetectPortPrint(ag); SCLogDebug("");

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

/**
 * \brief Copy and insert the new DetectPort, with a copy list of sigs
 *
 * \param de_ctx Pointer to the current detection engine context
 * \param head Pointer to the DetectPort list head
 * \param new Pointer to DetectPort to search in the DetectPort list
 *
 * \retval 0 if dp is added correctly
 */
int DetectPortInsertCopy(DetectEngineCtx *de_ctx, DetectPort **head,
                         DetectPort *new)
{
    DetectPort *copy = DetectPortCopySingle(de_ctx,new);
    if (copy == NULL)
        return -1;

    return DetectPortInsert(de_ctx, head, copy);
}

/**
 * \brief function for inserting a port group object. This also makes sure
 *         SigGroupContainer lists are handled correctly.
 *
 * \param de_ctx Pointer to the current detection engine context
 * \param head Pointer to the DetectPort list head
 * \param dp DetectPort to search in the DetectPort list
 *
 * \retval 1 inserted
 * \retval 0 not inserted, memory of new is freed
 * \retval -1 error
 * */
int DetectPortInsert(DetectEngineCtx *de_ctx, DetectPort **head,
                     DetectPort *new)
{
    if (new == NULL)
        return 0;

    //BUG_ON(new->next != NULL);
    //BUG_ON(new->prev != NULL);

    /* see if it already exists or overlaps with existing ag's */
    if (*head != NULL) {
        DetectPort *cur = NULL;
        int r = 0;

        for (cur = *head; cur != NULL; cur = cur->next) {
            r = DetectPortCmp(new,cur);
            BUG_ON(r == PORT_ER);

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

            } else {
                DetectPort *c = NULL;
                r = DetectPortCut(de_ctx, cur, new, &c);
                if (r == -1)
                    goto error;

                r = DetectPortInsert(de_ctx, head, new);
                if (r == -1)
                    goto error;

                if (c != NULL) {
                    SCLogDebug("inserting C (%p)", c);
                    if (SCLogDebugEnabled()) {
                        DetectPortPrint(c);
                    }
                    r = DetectPortInsert(de_ctx, head, c);
                    if (r == -1)
                        goto error;
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

/**
 * \brief Function that cuts port groups and merge them
 *
 * \param de_ctx Pointer to the current detection engine context
 * \param a pointer to DetectPort "a"
 * \param b pointer to DetectPort "b"
 * \param c pointer to DetectPort "c"
 *
 * \retval 0 ok
 * \retval -1 error
 * */
static int DetectPortCut(DetectEngineCtx *de_ctx, DetectPort *a,
                         DetectPort *b, DetectPort **c)
{
    uint32_t a_port1 = a->port;
    uint32_t a_port2 = a->port2;
    uint32_t b_port1 = b->port;
    uint32_t b_port2 = b->port2;
    DetectPort *tmp = NULL;

    /* default to NULL */
    *c = NULL;

    int r = DetectPortCmp(a,b);
    BUG_ON(r != PORT_ES && r != PORT_EB && r != PORT_LE && r != PORT_GE);

    /* get a place to temporary put sigs lists */
    tmp = DetectPortInit();
    if (tmp == NULL) {
        goto error;
    }
    memset(tmp, 0, sizeof(DetectPort));

    /**
     * We have 3 parts: [aaa[abab]bbb]
     * part a: a_port1 <-> b_port1 - 1
     * part b: b_port1 <-> a_port2
     * part c: a_port2 + 1 <-> b_port2
     */
    if (r == PORT_LE) {
        SCLogDebug("cut r == PORT_LE");
        a->port = a_port1;
        a->port2 = b_port1 - 1;

        b->port = b_port1;
        b->port2 = a_port2;

        DetectPort *tmp_c;
        tmp_c = DetectPortInit();
        if (tmp_c == NULL) {
            goto error;
        }
        *c = tmp_c;

        tmp_c->port = a_port2 + 1;
        tmp_c->port2 = b_port2;

        SigGroupHeadCopySigs(de_ctx,b->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh); /* copy a to b */

        tmp_c->cnt += b->cnt;
        b->cnt += a->cnt;

    /**
     * We have 3 parts: [bbb[baba]aaa]
     * part a: b_port1 <-> a_port1 - 1
     * part b: a_port1 <-> b_port2
     * part c: b_port2 + 1 <-> a_port2
     */
    } else if (r == PORT_GE) {
        SCLogDebug("cut r == PORT_GE");
        a->port = b_port1;
        a->port2 = a_port1 - 1;

        b->port = a_port1;
        b->port2 = b_port2;

        DetectPort *tmp_c;
        tmp_c = DetectPortInit();
        if (tmp_c == NULL) {
            goto error;
        }
        *c = tmp_c;

        tmp_c->port = b_port2 + 1;
        tmp_c->port2 = a_port2;

        /**
         * 'a' gets clean and then 'b' sigs
         * 'b' gets clean, then 'a' then 'b' sigs
         * 'c' gets 'a' sigs
         */
        SigGroupHeadCopySigs(de_ctx,a->sh,&tmp->sh); /* store old a list */
        SigGroupHeadClearSigs(a->sh); /* clean a list */
        SigGroupHeadCopySigs(de_ctx,tmp->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx,b->sh,&a->sh); /* copy old b to a */
        SigGroupHeadCopySigs(de_ctx,tmp->sh,&b->sh);/* prepend old a before b */

        SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

        tmp->cnt += a->cnt;
        a->cnt = 0;
        tmp_c->cnt += tmp->cnt;
        a->cnt += b->cnt;
        b->cnt += tmp->cnt;
        tmp->cnt = 0;

    /**
     * We have 2 or three parts:
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
        SCLogDebug("cut r == PORT_ES");
        if (a_port1 == b_port1) {
            SCLogDebug("1");
            a->port = a_port1;
            a->port2 = a_port2;

            b->port  = a_port2 + 1;
            b->port2 = b_port2;

            /** 'b' overlaps 'a' so 'a' needs the 'b' sigs */
            SigGroupHeadCopySigs(de_ctx,b->sh,&a->sh);
            a->cnt += b->cnt;

        } else if (a_port2 == b_port2) {
            SCLogDebug("2");
            a->port = b_port1;
            a->port2 = a_port1 - 1;

            b->port = a_port1;
            b->port2 = a_port2;

            /* [bbb[baba]] will be transformed into
             * [aaa][bbb]
             * steps: copy b sigs to tmp
             *        a overlaps b, so copy a to b
             *        clear a
             *        copy tmp to a */
            SigGroupHeadCopySigs(de_ctx,b->sh,&tmp->sh); /* store old a list */
            tmp->cnt = b->cnt;
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            b->cnt += a->cnt;
            SigGroupHeadClearSigs(a->sh); /* clean a list */
            SigGroupHeadCopySigs(de_ctx,tmp->sh,&a->sh);/* merge old a with b */
            a->cnt = tmp->cnt;
            SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */
        } else {
            SCLogDebug("3");
            a->port = b_port1;
            a->port2 = a_port1 - 1;

            b->port = a_port1;
            b->port2 = a_port2;

            DetectPort *tmp_c;
            tmp_c = DetectPortInit();
            if (tmp_c == NULL) {
                goto error;
            }
            *c = tmp_c;

            tmp_c->port = a_port2 + 1;
            tmp_c->port2 = b_port2;

            /**
             * 'a' gets clean and then 'b' sigs
             * 'b' gets clean, then 'a' then 'b' sigs
             * 'c' gets 'b' sigs
             */
            SigGroupHeadCopySigs(de_ctx,a->sh,&tmp->sh); /* store old a list */
            SigGroupHeadClearSigs(a->sh); /* clean a list */
            SigGroupHeadCopySigs(de_ctx,b->sh,&tmp_c->sh); /* copy old b to c */
            SigGroupHeadCopySigs(de_ctx,b->sh,&a->sh); /* copy old b to a */
            SigGroupHeadCopySigs(de_ctx,tmp->sh,&b->sh);/* merge old a with b */

            SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

            tmp->cnt += a->cnt;
            a->cnt = 0;
            tmp_c->cnt += b->cnt;
            a->cnt += b->cnt;
            b->cnt += tmp->cnt;
            tmp->cnt = 0;
        }
    /**
     * We have 2 or three parts:
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
        SCLogDebug("cut r == PORT_EB");
        if (a_port1 == b_port1) {
            SCLogDebug("1");
            a->port = b_port1;
            a->port2 = b_port2;

            b->port = b_port2 + 1;
            b->port2 = a_port2;

            /** 'b' overlaps 'a' so 'a' needs the 'b' sigs */
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

        } else if (a_port2 == b_port2) {
            SCLogDebug("2");

            a->port = a_port1;
            a->port2 = b_port1 - 1;

            b->port = b_port1;
            b->port2 = b_port2;

            /** 'a' overlaps 'b' so 'b' needs the 'a' sigs */
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);

            b->cnt += a->cnt;

        } else {
            SCLogDebug("3");
            a->port = a_port1;
            a->port2 = b_port1 - 1;

            b->port = b_port1;
            b->port2 = b_port2;

            DetectPort *tmp_c;
            tmp_c = DetectPortInit();
            if (tmp_c == NULL) {
                goto error;
            }
            *c = tmp_c;

            tmp_c->port = b_port2 + 1;
            tmp_c->port2 = a_port2;

            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            SigGroupHeadCopySigs(de_ctx,a->sh,&tmp_c->sh);

            b->cnt += a->cnt;
            tmp_c->cnt += a->cnt;
        }
    }

    if (tmp != NULL) {
        DetectPortFree(tmp);
    }
    return 0;

error:
    if (tmp != NULL)
        DetectPortFree(tmp);
    return -1;
}

/**
 * \brief Function that cuts port groups implementing group negation
 *
 * \param a pointer to DetectPort "a"
 * \param b pointer to DetectPort "b"
 *
 * \retval 0 ok
 * \retval -1 error
 * */
static int DetectPortCutNot(DetectPort *a, DetectPort **b)
{
    uint16_t a_port1 = a->port;
    uint16_t a_port2 = a->port2;

    /* default to NULL */
    *b = NULL;

    if (a_port1 != 0x0000 && a_port2 != 0xFFFF) {
        a->port = 0x0000;
        a->port2 = a_port1 - 1;

        DetectPort *tmp_b;
        tmp_b = DetectPortInit();
        if (tmp_b == NULL) {
            goto error;
        }

        tmp_b->port = a_port2 + 1;
        tmp_b->port2 = 0xFFFF;
        *b = tmp_b;

    } else if (a_port1 == 0x0000 && a_port2 != 0xFFFF) {
        a->port = a_port2 + 1;
        a->port2 = 0xFFFF;

    } else if (a_port1 != 0x0000 && a_port2 == 0xFFFF) {
        a->port = 0x0000;
        a->port2 = a_port1 - 1;
    } else {
        goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * \brief Function that compare port groups
 *
 * \param a pointer to DetectPort "a"
 * \param b pointer to DetectPort "b"
 *
 * \retval PORT_XX (Port enum value, XX is EQ, ES, EB, LE, etc)
 * \retval PORT_ER on error
 * */
int DetectPortCmp(DetectPort *a, DetectPort *b)
{
    /* check any */
    if ((a->flags & PORT_FLAG_ANY) && (b->flags & PORT_FLAG_ANY))
        return PORT_EQ;
    if ((a->flags & PORT_FLAG_ANY) && !(b->flags & PORT_FLAG_ANY))
        return PORT_LT;
    if (!(a->flags & PORT_FLAG_ANY) && (b->flags & PORT_FLAG_ANY))
        return PORT_GT;

    uint16_t a_port1 = a->port;
    uint16_t a_port2 = a->port2;
    uint16_t b_port1 = b->port;
    uint16_t b_port2 = b->port2;

    /* PORT_EQ */
    if (a_port1 == b_port1 && a_port2 == b_port2) {
        //SCLogDebug("PORT_EQ");
        return PORT_EQ;
    /* PORT_ES */
    } else if (a_port1 >= b_port1 && a_port1 <= b_port2 && a_port2 <= b_port2) {
        //SCLogDebug("PORT_ES");
        return PORT_ES;
    /* PORT_EB */
    } else if (a_port1 <= b_port1 && a_port2 >= b_port2) {
        //SCLogDebug("PORT_EB");
        return PORT_EB;
    } else if (a_port1 < b_port1 && a_port2 < b_port2 && a_port2 >= b_port1) {
        //SCLogDebug("PORT_LE");
        return PORT_LE;
    } else if (a_port1 < b_port1 && a_port2 < b_port2) {
        //SCLogDebug("PORT_LT");
        return PORT_LT;
    } else if (a_port1 > b_port1 && a_port1 <= b_port2 && a_port2 > b_port2) {
        //SCLogDebug("PORT_GE");
        return PORT_GE;
    } else if (a_port1 > b_port2) {
        //SCLogDebug("PORT_GT");
        return PORT_GT;
    } else {
        /* should be unreachable */
        BUG_ON(1);
    }

    return PORT_ER;
}

/**
 * \brief Function that return a copy of DetectPort src
 *
 * \param de_ctx Pointer to the current Detection Engine Context
 * \param src Pointer to a DetectPort group to copy
 *
 * \retval Pointer to a DetectPort instance (copy of src)
 * \retval NULL on error
 * */
DetectPort *DetectPortCopy(DetectEngineCtx *de_ctx, DetectPort *src)
{
    if (src == NULL)
        return NULL;

    DetectPort *dst = DetectPortInit();
    if (dst == NULL) {
        goto error;
    }

    dst->port = src->port;
    dst->port2 = src->port2;

    if (src->next != NULL) {
        dst->next = DetectPortCopy(de_ctx, src->next);
        if (dst->next != NULL) {
            dst->next->prev = dst;
        }
    }

    return dst;
error:
    return NULL;
}

/**
 * \brief Function that return a copy of DetectPort src sigs
 *
 * \param de_ctx Pointer to the current Detection Engine Context
 * \param src Pointer to a DetectPort group to copy
 *
 * \retval Pointer to a DetectPort instance (copy of src)
 * \retval NULL on error
 * */
DetectPort *DetectPortCopySingle(DetectEngineCtx *de_ctx,DetectPort *src)
{
    if (src == NULL)
        return NULL;

    DetectPort *dst = DetectPortInit();
    if (dst == NULL) {
        goto error;
    }

    dst->port = src->port;
    dst->port2 = src->port2;

    SigGroupHeadCopySigs(de_ctx,src->sh,&dst->sh);

    return dst;
error:
    return NULL;
}

/**
 * \brief Function Match to Match a port against a DetectPort group
 *
 * \param dp Pointer to DetectPort group where we try to match the port
 * \param port To compare/match
 *
 * \retval 1 if port is in the range (it match)
 * \retval 0 if port is not in the range
 * */
int DetectPortMatch(DetectPort *dp, uint16_t port)
{
    if (port >= dp->port &&
        port <= dp->port2) {
        return 1;
    }

    return 0;
}

/**
 * \brief Helper function that print the DetectPort info
 * \retval none
 */
void DetectPortPrint(DetectPort *dp)
{
    if (dp == NULL)
        return;

    if (dp->flags & PORT_FLAG_ANY) {
        SCLogDebug("=> port %p: ANY", dp);
//        printf("ANY");
    } else {
        SCLogDebug("=> port %p %" PRIu32 "-%" PRIu32 "", dp, dp->port, dp->port2);
//        printf("%" PRIu32 "-%" PRIu32 "", dp->port, dp->port2);
    }
}

/**
 * \brief Function that find the group matching address in a group head
 *
 * \param dp Pointer to DetectPort group where we try to find the group
 * \param port port to search/lookup
 *
 * \retval Pointer to the DetectPort group of our port if it matched
 * \retval NULL if port is not in the list
 * */
DetectPort *
DetectPortLookupGroup(DetectPort *dp, uint16_t port)
{
    DetectPort *p = dp;

    if (dp == NULL)
        return NULL;

    for ( ; p != NULL; p = p->next) {
        if (DetectPortMatch(p,port) == 1) {
            //SCLogDebug("match, port %" PRIu32 ", dp ", port);
            //DetectPortPrint(p); SCLogDebug("");
            return p;
        }
    }

    return NULL;
}

/**
 * \brief Function to join the source group to the target and its members
 *
 * \param de_ctx Pointer to the current Detection Engine Context
 * \param target Pointer to DetectPort group where the source is joined
 * \param source Pointer to DetectPort group that will join into the target
 *
 * \retval -1 on error
 * \retval 0 on success
 * */
int DetectPortJoin(DetectEngineCtx *de_ctx, DetectPort *target,
                   DetectPort *source)
{
    if (target == NULL || source == NULL)
        return -1;

    target->cnt += source->cnt;
    SigGroupHeadCopySigs(de_ctx,source->sh,&target->sh);

    if (source->port < target->port)
        target->port = source->port;

    if (source->port2 > target->port2)
        target->port2 = source->port2;

    return 0;
}

/******************* parsing routines ************************/

/**
 * \brief Wrapper function that call the internal/real function
 *        to insert the new DetectPort
 * \param head Pointer to the head of the DetectPort group list
 * \param new Pointer to the new DetectPort group list
 *
 * \retval 1 inserted
 * \retval 0 not inserted, memory of new is freed
 * \retval -1 error
 */
static int DetectPortParseInsert(DetectPort **head, DetectPort *new)
{
    return DetectPortInsert(NULL, head, new);
}

/**
 * \brief Function to parse and insert the string in the DetectPort head list
 *
 * \param head Pointer to the head of the DetectPort group list
 * \param s Pointer to the port string
 *
 * \retval 0 on success
 * \retval -1 on error
 */
static int DetectPortParseInsertString(DetectPort **head, char *s)
{
    DetectPort *ad = NULL, *ad_any = NULL;
    int r = 0;
    char port_any = FALSE;

    SCLogDebug("head %p, *head %p, s %s", head, *head, s);

    /** parse the address */
    ad = PortParse(s);
    if (ad == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT," failed to parse port \"%s\"",s);
        return -1;
    }

    if (ad->flags & PORT_FLAG_ANY) {
        port_any = TRUE;
    }

    /** handle the not case, we apply the negation then insert the part(s) */
    if (ad->flags & PORT_FLAG_NOT) {
        DetectPort *ad2 = NULL;

        if (DetectPortCutNot(ad, &ad2) < 0) {
            goto error;
        }

        /** normally a 'not' will result in two ad's unless the 'not' is on the
         *  start or end of the address space(e.g. 0.0.0.0 or 255.255.255.255)
         */
        if (ad2 != NULL) {
            if (DetectPortParseInsert(head, ad2) < 0) {
                if (ad2 != NULL) SCFree(ad2);
                goto error;
            }
        }
    }

    r = DetectPortParseInsert(head, ad);
    if (r < 0)
        goto error;

    /** if any, insert 0.0.0.0/0 and ::/0 as well */
    if (r == 1 && port_any == TRUE) {
        SCLogDebug("inserting 0:65535 as port is \"any\"");

        ad_any = PortParse("0:65535");
        if (ad_any == NULL)
            goto error;

        if (DetectPortParseInsert(head, ad_any) < 0)
	        goto error;
    }

    return 0;

error:
    SCLogError(SC_ERR_PORT_PARSE_INSERT_STRING,"DetectPortParseInsertString error");
    if (ad != NULL)
        DetectPortCleanupList(ad);
    if (ad_any != NULL)
        DetectPortCleanupList(ad_any);
    return -1;
}

/**
 * \brief Parses a port string and updates the 2 port heads with the
 *        port groups.
 *
 * \todo We don't seem to be handling negated cases, like [port,![!port,port]],
 *       since we pass around negate without keeping a count of ! with depth.
 *       Can solve this by keeping a count of the negations with depth, so that
 *       an even no of negations would count as no negation and an odd no of
 *       negations would count as a negation.
 *
 * \param gh     Pointer to the port group head that should hold port ranges
 *               that are not negated.
 * \param ghn    Pointer to the port group head that should hold port ranges
 *               that are negated.
 * \param s      Pointer to the character string holding the port to be
 *               parsed.
 * \param negate Flag that indicates if the receieved address string is negated
 *               or not.  0 if it is not, 1 it it is.
 *
 * \retval  0 On successfully parsing.
 * \retval -1 On failure.
 */
static int DetectPortParseDo(const DetectEngineCtx *de_ctx,
                             DetectPort **head, DetectPort **nhead,
                             char *s, int negate)
{
    size_t u = 0;
    size_t x = 0;
    int o_set = 0, n_set = 0, d_set = 0;
    int range = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[1024] = "";
    char *rule_var_port = NULL;
    int r = 0;

    SCLogDebug("head %p, *head %p, negate %d", head, *head, negate);

    for (u = 0, x = 0; u < size && x < sizeof(address); u++) {
        address[x] = s[u];
        x++;

        if (s[u] == ':')
            range = 1;

        if (range == 1 && s[u] == '!') {
            SCLogError(SC_ERR_NEGATED_VALUE_IN_PORT_RANGE,"Can't have a negated value in a range.");
            return -1;
        } else if (!o_set && s[u] == '!') {
            SCLogDebug("negation encountered");
            n_set = 1;
            x--;
        } else if (s[u] == '[') {
            if (!o_set) {
                o_set = 1;
                x = 0;
            }
            depth++;
        } else if (s[u] == ']') {
            if (depth == 1) {
                address[x - 1] = '\0';
                SCLogDebug("Parsed port from DetectPortParseDo - %s", address);
                x = 0;

                r = DetectPortParseDo(de_ctx, head, nhead, address, negate? negate: n_set);
                if (r == -1)
                    goto error;

                n_set = 0;
            }
            depth--;
            range = 0;
        } else if (depth == 0 && s[u] == ',') {
            if (o_set == 1) {
                o_set = 0;
            } else if (d_set == 1) {
                char *temp_rule_var_port = NULL,
                     *alloc_rule_var_port = NULL;

                address[x - 1] = '\0';

                rule_var_port = SCRuleVarsGetConfVar(de_ctx, address,
                                                     SC_RULE_VARS_PORT_GROUPS);
                if (rule_var_port == NULL)
                    goto error;
                if (strlen(rule_var_port) == 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "variable %s resolved "
                            "to nothing. This is likely a misconfiguration. "
                            "Note that a negated port needs to be quoted, "
                            "\"!$HTTP_PORTS\" instead of !$HTTP_PORTS. See issue #295.", s);
                    goto error;
                }
                temp_rule_var_port = rule_var_port;
                if (negate == 1 || n_set == 1) {
                    alloc_rule_var_port = SCMalloc(strlen(rule_var_port) + 3);
                    if (unlikely(alloc_rule_var_port == NULL))
                        goto error;
                    snprintf(alloc_rule_var_port, strlen(rule_var_port) + 3,
                             "[%s]", rule_var_port);
                    temp_rule_var_port = alloc_rule_var_port;
                }
                r = DetectPortParseDo(de_ctx, head, nhead, temp_rule_var_port,
                                  (negate + n_set) % 2);//negate? negate: n_set);
                if (r == -1)
                    goto error;

                d_set = 0;
                n_set = 0;
                if (alloc_rule_var_port != NULL)
                    SCFree(alloc_rule_var_port);
            } else {
                address[x - 1] = '\0';
                SCLogDebug("Parsed port from DetectPortParseDo - %s", address);

                if (negate == 0 && n_set == 0) {
                    r = DetectPortParseInsertString(head, address);
                } else {
                    r = DetectPortParseInsertString(nhead, address);
                }
                if (r == -1)
                    goto error;

                n_set = 0;
            }
            x = 0;
            range = 0;
        } else if (depth == 0 && s[u] == '$') {
            d_set = 1;
        } else if (depth == 0 && u == size-1) {
            range = 0;
            if (x == 1024) {
                address[x - 1] = '\0';
            } else {
                address[x] = '\0';
            }
            SCLogDebug("%s", address);
            x = 0;
            if (d_set == 1) {
                char *temp_rule_var_port = NULL,
                     *alloc_rule_var_port = NULL;

                rule_var_port = SCRuleVarsGetConfVar(de_ctx, address,
                                                     SC_RULE_VARS_PORT_GROUPS);
                if (rule_var_port == NULL)
                    goto error;
                if (strlen(rule_var_port) == 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "variable %s resolved "
                            "to nothing. This is likely a misconfiguration. "
                            "Note that a negated port needs to be quoted, "
                            "\"!$HTTP_PORTS\" instead of !$HTTP_PORTS. See issue #295.", s);
                    goto error;
                }
                temp_rule_var_port = rule_var_port;
                if ((negate + n_set) % 2) {
                    alloc_rule_var_port = SCMalloc(strlen(rule_var_port) + 3);
                    if (unlikely(alloc_rule_var_port == NULL))
                        goto error;
                    snprintf(alloc_rule_var_port, strlen(rule_var_port) + 3,
                            "[%s]", rule_var_port);
                    temp_rule_var_port = alloc_rule_var_port;
                }
                r = DetectPortParseDo(de_ctx, head, nhead, temp_rule_var_port,
                                  (negate + n_set) % 2);
                if (r == -1)
                    goto error;

                d_set = 0;
                if (alloc_rule_var_port != NULL)
                    SCFree(alloc_rule_var_port);
            } else {
                if (!((negate + n_set) % 2)) {
                    r = DetectPortParseInsertString(head,address);
                } else {
                    r = DetectPortParseInsertString(nhead,address);
                }
                if (r == -1)
                    goto error;
            }
            n_set = 0;
        }
    }

    if (depth > 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "not every port block was "
                "properly closed in \"%s\", %d missing closing brackets (]). "
                "Note: problem might be in a variable.", s, depth);
        goto error;
    } else if (depth < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "not every port block was "
                "properly opened in \"%s\", %d missing opening brackets ([). "
                "Note: problem might be in a variable.", s, depth*-1);
        goto error;
    }

    return 0;
error:
    return -1;
}

/**
 * \brief Check if the port group list covers the complete port space.
 * \retval 0 no
 * \retval 1 yes
 */
int DetectPortIsCompletePortSpace(DetectPort *p)
{
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
        if (p->port != next_port)
            return 0;

        if (p->port2 == 0xFFFF)
            return 1;

        next_port = p->port2 + 1;
    }

    return 0;
}

/**
 * \brief Helper function for the parsing process
 *
 * \param head Pointer to the head of the DetectPort group list
 * \param nhead Pointer to the new head of the DetectPort group list
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int DetectPortParseMergeNotPorts(DetectPort **head, DetectPort **nhead)
{
    DetectPort *ad = NULL;
    DetectPort *ag, *ag2;
    int r = 0;

    /** check if the full port space is negated */
    if (DetectPortIsCompletePortSpace(*nhead) == 1) {
        SCLogError(SC_ERR_COMPLETE_PORT_SPACE_NEGATED,"Complete port space is negated");
        goto error;
    }

    /**
     * step 0: if the head list is empty, but the nhead list isn't
     * we have a pure not thingy. In that case we add a 0:65535
     * first.
     */
    if (*head == NULL && *nhead != NULL) {
        SCLogDebug("inserting 0:65535 into head");
        r = DetectPortParseInsertString(head,"0:65535");
        if (r < 0) {
            goto error;
        }
    }

    /** step 1: insert our ghn members into the gh list */
    for (ag = *nhead; ag != NULL; ag = ag->next) {
        /** work with a copy of the ad so we can easily clean up
         * the ghn group later.
         */
        ad = DetectPortCopy(NULL, ag);
        if (ad == NULL) {
            goto error;
        }
        r = DetectPortParseInsert(head, ad);
        if (r < 0) {
            goto error;
        }
        ad = NULL;
    }

    /** step 2: pull the address blocks that match our 'not' blocks */
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
                /** store the next ptr and remove the group */
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
        SCLogError(SC_ERR_NO_PORTS_LEFT_AFTER_MERGE,"no ports left after merging ports with negated ports");
        goto error;
    }

    return 0;
error:
    if (ad != NULL)
        DetectPortFree(ad);
    return -1;
}

int DetectPortTestConfVars(void)
{
    SCLogDebug("Testing port conf vars for any misconfigured values");

    ConfNode *port_vars_node = ConfGetNode("vars.port-groups");
    if (port_vars_node == NULL) {
        return 0;
    }

    ConfNode *seq_node;
    TAILQ_FOREACH(seq_node, &port_vars_node->head, next) {
        SCLogDebug("Testing %s - %s\n", seq_node->name, seq_node->val);

        DetectPort *gh =  DetectPortInit();
        if (gh == NULL) {
            goto error;
        }
        DetectPort *ghn = NULL;

        if (seq_node->val == NULL) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                       "Port var \"%s\" probably has a sequence(something "
                       "in brackets) value set without any quotes. Please "
                       "quote it using \"..\".", seq_node->name);
            DetectPortCleanupList(gh);
            goto error;
        }

        int r = DetectPortParseDo(NULL, &gh, &ghn, seq_node->val, /* start with negate no */0);
        if (r < 0) {
            DetectPortCleanupList(gh);
            goto error;
        }

        if (DetectPortIsCompletePortSpace(ghn)) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                       "Port var - \"%s\" has the complete Port range negated "
                       "with it's value \"%s\".  Port space range is NIL. "
                       "Probably have a !any or a port range that supplies "
                       "a NULL address range", seq_node->name, seq_node->val);
            DetectPortCleanupList(gh);
            DetectPortCleanupList(ghn);
            goto error;
        }

        if (gh != NULL)
            DetectPortCleanupList(gh);
        if (ghn != NULL)
            DetectPortCleanupList(ghn);
    }

    return 0;
 error:
    return -1;
}


/**
 * \brief Function for parsing port strings
 *
 * \param head Pointer to the head of the DetectPort group list
 * \param str Pointer to the port string
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int DetectPortParse(const DetectEngineCtx *de_ctx,
                    DetectPort **head, char *str)
{
    int r;

    SCLogDebug("Port string to be parsed - str %s", str);

    /* negate port list */
    DetectPort *nhead = NULL;

    r = DetectPortParseDo(de_ctx, head, &nhead, str,/* start with negate no */0);
    if (r < 0)
        goto error;

    SCLogDebug("head %p %p, nhead %p", head, *head, nhead);

    /* merge the 'not' address groups */
    if (DetectPortParseMergeNotPorts(head, &nhead) < 0)
        goto error;

    /* free the temp negate head */
    DetectPortCleanupList(nhead);
    return 0;

error:
    DetectPortCleanupList(nhead);
    return -1;
}

/**
 * \brief Helper function for parsing port strings
 *
 * \param str Pointer to the port string
 *
 * \retval DetectPort pointer of the parse string on success
 * \retval NULL on error
 */
DetectPort *PortParse(char *str)
{
    char *port2 = NULL;
    DetectPort *dp = NULL;

    char portstr[16];
    strlcpy(portstr, str, sizeof(portstr));

    dp = DetectPortInit();
    if (dp == NULL)
        goto error;

    /* XXX better input validation */

    /* we dup so we can put a nul-termination in it later */
    char *port = portstr;

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

    return dp;

error:
    if (dp != NULL)
        DetectPortCleanupList(dp);
    return NULL;
}

/**
 * \brief Helper function to check if a parsed port is in the valid range
 *        of available ports
 *
 * \param str Pointer to the port string
 *
 * \retval 1 if port is in the valid range
 * \retval 0 if invalid
 */
int DetectPortIsValidRange(char *port)
{
    if(atoi(port) >= 0 && atoi(port) <= 65535)
        return 1;
    else
        return 0;
}
/********************** End parsing routines ********************/


/********************* Hash function routines *******************/
#define PORT_HASH_SIZE 1024

/**
 * \brief Generate a hash for a DetectPort group
 *
 * \param ht HashListTable
 * \param data Pointer to the DetectPort
 * \param datalen sizeof data (not used here atm)
 *
 * \retval uint32_t the value of the generated hash
 */
uint32_t DetectPortHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    DetectPort *p = (DetectPort *)data;
    uint32_t hash = p->port * p->port2;

    return hash % ht->array_size;
}

/**
 * \brief Function that return if the two DetectPort groups are equal or not
 *
 * \param data1 Pointer to the DetectPort 1
 * \param len1 sizeof data 1 (not used here atm)
 * \param data2 Pointer to the DetectPort 2
 * \param len2 sizeof data 2 (not used here atm)
 *
 * \retval 1 if the DetectPort groups are equal
 * \retval 0 if not equal
 */
char DetectPortCompareFunc(void *data1, uint16_t len1, void *data2,
                           uint16_t len2)
{
    DetectPort *p1 = (DetectPort *)data1;
    DetectPort *p2 = (DetectPort *)data2;

    if (p1->port2 == p2->port2 && p1->port == p2->port &&
        p1->flags == p2->flags)
        return 1;

    return 0;
}

void DetectPortFreeFunc(void *p)
{
    DetectPort *dp = (DetectPort *)p;
    DetectPortFree(dp);
}

/**
 * \brief Function that initialize the HashListTable of destination DetectPort
 *
 * \param de_ctx Pointer to the current DetectionEngineContext
 *
 * \retval 0 HashListTable initialization succes
 * \retval -1 Error
 */
int DetectPortDpHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->dport_hash_table = HashListTableInit(PORT_HASH_SIZE,
                               DetectPortHashFunc, DetectPortCompareFunc, DetectPortFreeFunc);
    if (de_ctx->dport_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

/**
 * \brief Function that free the HashListTable of destination DetectPort
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 */
void DetectPortDpHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->dport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->dport_hash_table);
    de_ctx->dport_hash_table = NULL;
}

/**
 * \brief Function that reset the HashListTable of destination DetectPort
 * (Free and Initialize it)
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 */
void DetectPortDpHashReset(DetectEngineCtx *de_ctx)
{
    DetectPortDpHashFree(de_ctx);
    DetectPortDpHashInit(de_ctx);
}

/**
 * \brief Function that add a destination DetectPort into the hashtable
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 * \param p Pointer to the DetectPort to add
 */
int DetectPortDpHashAdd(DetectEngineCtx *de_ctx, DetectPort *p)
{
    return HashListTableAdd(de_ctx->dport_hash_table, (void *)p, 0);
}

/**
 * \brief Function that search a destination DetectPort in the hashtable
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 * \param p Pointer to the DetectPort to search
 */
DetectPort *DetectPortDpHashLookup(DetectEngineCtx *de_ctx, DetectPort *p)
{
    DetectPort *rp = HashListTableLookup(de_ctx->dport_hash_table,
                                         (void *)p, 0);
    return rp;
}

/**
 * \brief Function that initialize the HashListTable of source DetectPort
 *
 * \param de_ctx Pointer to the current DetectionEngineContext
 *
 * \retval 0 HashListTable initialization succes
 * \retval -1 Error
 */
int DetectPortSpHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->sport_hash_table = HashListTableInit(PORT_HASH_SIZE,
                               DetectPortHashFunc, DetectPortCompareFunc, DetectPortFreeFunc);
    if (de_ctx->sport_hash_table == NULL)
        goto error;

    return 0;
error:
    return -1;
}

/**
 * \brief Function that free the HashListTable of source DetectPort
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 */
void DetectPortSpHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sport_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->sport_hash_table);
    de_ctx->sport_hash_table = NULL;
}

/**
 * \brief Function that reset the HashListTable of source DetectPort
 * (Free and Initialize it)
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 */
void DetectPortSpHashReset(DetectEngineCtx *de_ctx)
{
    DetectPortSpHashFree(de_ctx);
    DetectPortSpHashInit(de_ctx);
}

/**
 * \brief Function that add a source DetectPort into the hashtable
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 * \param p Pointer to the DetectPort to add
 */
int DetectPortSpHashAdd(DetectEngineCtx *de_ctx, DetectPort *p)
{
    return HashListTableAdd(de_ctx->sport_hash_table, (void *)p, 0);
}

/**
 * \brief Function that search a source DetectPort in the hashtable
 *
 * \param de_ctx Pointer to the current DetectionEngineCtx
 * \param p Pointer to the DetectPort to search
 */
DetectPort *DetectPortSpHashLookup(DetectEngineCtx *de_ctx, DetectPort *p)
{
    DetectPort *rp = HashListTableLookup(de_ctx->sport_hash_table,
                                         (void *)p, 0);
    return rp;
}

/*---------------------- Unittests -------------------------*/

#ifdef UNITTESTS

/**
 * \test Check if a DetectPort is properly allocated
 */
int PortTestParse01 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"80");
    if (r == 0) {
        DetectPortFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test Check if two ports are properly allocated in the DetectPort group
 */
int PortTestParse02 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"80");
    if (r == 0) {
        r = DetectPortParse(NULL,&dd,"22");
        if (r == 0) {
            result = 1;
        }

        DetectPortCleanupList(dd);
        return result;
    }

    return result;
}

/**
 * \test Check if two port ranges are properly allocated in the DetectPort group
 */
int PortTestParse03 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"80:88");
    if (r == 0) {
        r = DetectPortParse(NULL,&dd,"85:100");
        if (r == 0) {
            result = 1;
        }

        DetectPortCleanupList(dd);

        return result;
    }

    return result;
}

/**
 * \test Check if a negated port range is properly allocated in the DetectPort
 */
int PortTestParse04 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"!80:81");
    if (r == 0) {
        DetectPortCleanupList(dd);
        return 1;
    }

    return 0;
}

/**
 * \test Check if a negated port range is properly fragmented in the allowed
 *       real groups, ex !80:81 should allow 0:79 and 82:65535
 */
int PortTestParse05 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"!80:81");
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

/**
 * \test Check if we copy a DetectPort correctly
 */
int PortTestParse06 (void)
{
    DetectPort *dd = NULL, *copy = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"22");
    if (r != 0)
        goto end;

    r = DetectPortParse(NULL,&dd,"80");
    if (r != 0)
        goto end;

    r = DetectPortParse(NULL,&dd,"143");
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

    if (copy->port != 22 || copy->next->port != 80 ||
        copy->next->next->port != 143)
        goto end;

    result = 1;

end:
    if (copy != NULL)
        DetectPortCleanupList(copy);
    if (dd != NULL)
        DetectPortCleanupList(dd);
    return result;
}

/**
 * \test Check if a negated port range is properly fragmented in the allowed
 *       real groups
 */
int PortTestParse07 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"!21:902");
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

/**
 * \test Check if we dont allow invalid port range specification
 */
int PortTestParse08 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"[80:!80]");
    if (r == 0)
        goto end;

    DetectPortCleanupList(dd);
    result = 1;
end:
    return result;
}

/**
 * \test Check if we autocomplete correctly an open range
 */
int PortTestParse09 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"1024:");
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

/**
 * \test Test we don't allow a port that is too big
 */
int PortTestParse10 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"77777777777777777777777777777777777777777777");
    if (r != 0) {
        result = 1 ;
        goto end;
    }

    DetectPortFree(dd);

end:
    return result;
}

/**
 * \test Test second port of range being too big
 */
int PortTestParse11 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"1024:65536");
    if (r != 0) {
        result = 1 ;
        goto end;
    }

    DetectPortFree(dd);

end:
    return result;
}

/**
 * \test Test second port of range being just right
 */
int PortTestParse12 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"1024:65535");
    if (r != 0) {
        goto end;
    }

    DetectPortFree(dd);

    result = 1 ;
end:
    return result;
}

/**
 * \test Test first port of range being too big
 */
int PortTestParse13 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"65536:65535");
    if (r != 0) {
        result = 1 ;
        goto end;
    }

    DetectPortFree(dd);

end:
    return result;
}

/**
 * \test Test merging port groups
 */
int PortTestParse14 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParseInsertString(&dd, "0:100");
    if (r != 0)
        goto end;
    r = DetectPortParseInsertString(&dd, "1000:65535");
    if (r != 0 || dd->next == NULL)
        goto end;

    result = 1;
    result &= (dd->port == 0) ? 1 : 0;
    result &= (dd->port2 == 100) ? 1 : 0;
    result &= (dd->next->port == 1000) ? 1 : 0;
    result &= (dd->next->port2 == 65535) ? 1 : 0;

    DetectPortFree(dd);

end:
    return result;
}

/**
 * \test Test merging negated port groups
 */
int PortTestParse15 (void)
{
    DetectPort *dd = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"![0:100,1000:3000]");
    if (r != 0 || dd->next == NULL)
        goto end;

    result = 1;
    result &= (dd->port == 101) ? 1 : 0;
    result &= (dd->port2 == 999) ? 1 : 0;
    result &= (dd->next->port == 3001) ? 1 : 0;
    result &= (dd->next->port2 == 65535) ? 1 : 0;

    DetectPortFree(dd);

end:
    return result;
}

/**
 * \test Test parse, copy and cmp functions
 */
int PortTestParse16 (void)
{
    DetectPort *dd = NULL, *copy = NULL;
    int result = 0;

    int r = DetectPortParse(NULL,&dd,"22");
    if (r != 0)
        goto end;

    r = DetectPortParse(NULL,&dd,"80");
    if (r != 0)
        goto end;

    r = DetectPortParse(NULL,&dd,"143");
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

    if (copy->next->prev != copy)
        goto end;

    result = 1;

end:
    if (copy != NULL)
        DetectPortCleanupList(copy);
    if (dd != NULL)
        DetectPortCleanupList(dd);
    return result;
}
/**
 * \test Test general functions
 */
int PortTestFunctions01(void)
{
    DetectPort *head = NULL;
    DetectPort *dp1= NULL;
    int result = 0;

    /* Parse */
    int r = DetectPortParse(NULL,&head,"![0:100,1000:65535]");
    if (r != 0 || head->next != NULL)
        goto end;

    /* We should have only one DetectPort */
    if (!(head->port == 101))
        goto end;
    if (!(head->port2 == 999))
        goto end;
    if (!(head->next == NULL))
        goto end;

    r = DetectPortParse(NULL, &dp1,"2000:3000");
    if (r != 0 || dp1->next != NULL)
        goto end;
    if (!(dp1->port == 2000))
        goto end;
    if (!(dp1->port2 == 3000))
        goto end;

    /* Add */
    r = DetectPortAdd(&head, dp1);
    if (r != 0 || head->next == NULL)
        goto end;
    if (!(head->port == 101))
        goto end;
    if (!(head->port2 == 999))
        goto end;
    if (!(head->next->port == 2000))
        goto end;
    if (!(head->next->port2 == 3000))
        goto end;

    /* Match */
    if (!DetectPortMatch(head, 150))
        goto end;
    if (DetectPortMatch(head->next, 1500))
        goto end;
    if ((DetectPortMatch(head, 3500)))
        goto end;
    if ((DetectPortMatch(head, 50)))
        goto end;

    result = 1;
end:
    if (dp1 != NULL)
        DetectPortFree(dp1);
    if (head != NULL)
        DetectPortFree(head);
    return result;
}

/**
 * \test Test general functions
 */
int PortTestFunctions02(void)
{
    DetectPort *head = NULL;
    DetectPort *dp1= NULL;
    DetectPort *dp2= NULL;
    int result = 0;

    /* Parse */
    int r = DetectPortParse(NULL,&head, "![0:100,1000:65535]");
    if (r != 0 || head->next != NULL)
        goto end;

    r = DetectPortParse(NULL, &dp1, "!200:300");
    if (r != 0 || dp1->next == NULL)
        goto end;

    /* Merge Nots */
    r = DetectPortParseMergeNotPorts(&head, &dp1);
    if (r != 0 || head->next != NULL)
        goto end;

    r = DetectPortParse(NULL, &dp2, "!100:500");
    if (r != 0 || dp2->next == NULL)
        goto end;

    /* Merge Nots */
    r = DetectPortParseMergeNotPorts(&head, &dp2);
    if (r != 0 || head->next != NULL)
        goto end;

    if (!(head->port == 200))
        goto end;
    if (!(head->port2 == 300))
        goto end;

    result = 1;

end:
    if (dp1 != NULL)
        DetectPortFree(dp1);
    if (dp2 != NULL)
        DetectPortFree(dp2);
    if (head != NULL)
        DetectPortFree(head);
    return result;
}

/**
 * \test Test general functions
 */
int PortTestFunctions03(void)
{
    DetectPort *dp1= NULL;
    DetectPort *dp2= NULL;
    DetectPort *dp3= NULL;
    int result = 0;

    int r = DetectPortParse(NULL, &dp1, "200:300");
    if (r != 0)
        goto end;

    r = DetectPortParse(NULL, &dp2, "250:300");
    if (r != 0)
        goto end;

    /* Cut */
    DetectPortCut(NULL, dp1, dp2, &dp3);
    if (r != 0)
        goto end;

    if (!(dp1->port == 200))
        goto end;
    if (!(dp1->port2 == 249))
        goto end;
    if (!(dp2->port == 250))
        goto end;
    if (!(dp2->port2 == 300))
        goto end;

    dp1->port = 0;
    dp1->port2 = 500;
    dp2->port = 250;
    dp2->port2 = 750;

    /* Cut */
    DetectPortCut(NULL, dp1, dp2, &dp3);
    if (r != 0)
        goto end;
    if (!(dp1->port == 0))
        goto end;
    if (!(dp1->port2 == 249))
        goto end;
    if (!(dp2->port == 250))
        goto end;
    if (!(dp2->port2 == 500))
        goto end;
    if (!(dp3->port == 501))
        goto end;
    if (!(dp3->port2 == 750))
        goto end;

    result = 1;

end:
    if (dp1 != NULL)
        DetectPortFree(dp1);
    if (dp2 != NULL)
        DetectPortFree(dp2);
    if (dp3 != NULL)
        DetectPortFree(dp3);
    return result;
}

/**
 * \test Test general functions
 */
int PortTestFunctions04(void)
{
    DetectPort *dp1= NULL;
    DetectPort *dp2= NULL;
    int result = 0;

    int r = DetectPortParse(NULL, &dp1, "200:300");
    if (r != 0)
        goto end;

    dp2 = DetectPortInit();

    /* Cut Not */
    DetectPortCutNot(dp1, &dp2);
    if (r != 0)
        goto end;

    if (!(dp1->port == 0))
        goto end;
    if (!(dp1->port2 == 199))
        goto end;
    if (!(dp2->port == 301))
        goto end;
    if (!(dp2->port2 == 65535))
        goto end;

    result = 1;
end:
    if (dp1 != NULL)
        DetectPortFree(dp1);
    if (dp2 != NULL)
        DetectPortFree(dp2);
    return result;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions05(void)
{
    DetectPort *dp1 = NULL;
    DetectPort *dp2 = NULL;
    DetectPort *dp3 = NULL;
    int result = 0;
    int r = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature s[2];
    memset(s,0x00,sizeof(s));

    s[0].num = 0;
    s[1].num = 1;

    r = DetectPortParse(NULL, &dp1, "1024:65535");
    if (r != 0) {
        printf("r != 0 but %d: ", r);
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &dp1->sh, &s[0]);

    r = DetectPortParse(NULL, &dp2, "any");
    if (r != 0) {
        printf("r != 0 but %d: ", r);
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &dp2->sh, &s[1]);

    SCLogDebug("dp1");
    DetectPortPrint(dp1);
    SCLogDebug("dp2");
    DetectPortPrint(dp2);

    DetectPortInsert(de_ctx, &dp3, dp1);
    DetectPortInsert(de_ctx, &dp3, dp2);

    if (dp3 == NULL)
        goto end;

    SCLogDebug("dp3");
    DetectPort *x = dp3;
    for ( ; x != NULL; x = x->next) {
        DetectPortPrint(x);
        //SigGroupHeadPrintSigs(de_ctx, x->sh);
    }

    DetectPort *one = dp3;
    DetectPort *two = dp3->next;

    int sig = 0;
    if ((one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(two->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'two', but it shouldn't: ", sig);
        goto end;
    }

    result = 1;
end:
    if (dp1 != NULL)
        DetectPortFree(dp1);
    if (dp2 != NULL)
        DetectPortFree(dp2);
    return result;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions06(void)
{
    DetectPort *dp1 = NULL;
    DetectPort *dp2 = NULL;
    DetectPort *dp3 = NULL;
    int result = 0;
    int r = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature s[2];
    memset(s,0x00,sizeof(s));

    s[0].num = 0;
    s[1].num = 1;

    r = DetectPortParse(NULL, &dp1, "1024:65535");
    if (r != 0) {
        printf("r != 0 but %d: ", r);
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &dp1->sh, &s[0]);

    r = DetectPortParse(NULL, &dp2, "any");
    if (r != 0) {
        printf("r != 0 but %d: ", r);
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &dp2->sh, &s[1]);

    SCLogDebug("dp1");
    DetectPortPrint(dp1);
    SCLogDebug("dp2");
    DetectPortPrint(dp2);

    DetectPortInsert(de_ctx, &dp3, dp2);
    DetectPortInsert(de_ctx, &dp3, dp1);

    if (dp3 == NULL)
        goto end;

    SCLogDebug("dp3");
    DetectPort *x = dp3;
    for ( ; x != NULL; x = x->next) {
        DetectPortPrint(x);
        //SigGroupHeadPrintSigs(de_ctx, x->sh);
    }

    DetectPort *one = dp3;
    DetectPort *two = dp3->next;

    int sig = 0;
    if ((one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(two->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'two', but it shouldn't: ", sig);
        goto end;
    }

    result = 1;
end:
    if (dp1 != NULL)
        DetectPortFree(dp1);
    if (dp2 != NULL)
        DetectPortFree(dp2);
    return result;
}

/**
 * \test Test packet Matches
 * \param raw_eth_pkt pointer to the ethernet packet
 * \param pktsize size of the packet
 * \param sig pointer to the signature to test
 * \param sid sid number of the signature
 * \retval return 1 if match
 * \retval return 0 if not
 */
int PortTestMatchReal(uint8_t *raw_eth_pkt, uint16_t pktsize, char *sig,
                      uint32_t sid)
{
    int result = 0;
    FlowInitConfig(FLOW_QUIET);
    Packet *p = UTHBuildPacketFromEth(raw_eth_pkt, pktsize);
    result = UTHPacketMatchSig(p, sig);
    PACKET_RECYCLE(p);
    FlowShutdown();
    return result;
}

/**
 * \brief Wrapper for PortTestMatchReal
 */
int PortTestMatchRealWrp(char *sig, uint32_t sid)
{
    /* Real HTTP packeth doing a GET method
     * tcp.sport=47370 tcp.dport=80
     * ip.src=192.168.28.131 ip.dst=192.168.1.1
     */
    uint8_t raw_eth_pkt[] = {
        0x00,0x50,0x56,0xea,0x00,0xbd,0x00,0x0c,
        0x29,0x40,0xc8,0xb5,0x08,0x00,0x45,0x00,
        0x01,0xa8,0xb9,0xbb,0x40,0x00,0x40,0x06,
        0xe0,0xbf,0xc0,0xa8,0x1c,0x83,0xc0,0xa8,
        0x01,0x01,0xb9,0x0a,0x00,0x50,0x6f,0xa2,
        0x92,0xed,0x7b,0xc1,0xd3,0x4d,0x50,0x18,
        0x16,0xd0,0xa0,0x6f,0x00,0x00,0x47,0x45,
        0x54,0x20,0x2f,0x20,0x48,0x54,0x54,0x50,
        0x2f,0x31,0x2e,0x31,0x0d,0x0a,0x48,0x6f,
        0x73,0x74,0x3a,0x20,0x31,0x39,0x32,0x2e,
        0x31,0x36,0x38,0x2e,0x31,0x2e,0x31,0x0d,
        0x0a,0x55,0x73,0x65,0x72,0x2d,0x41,0x67,
        0x65,0x6e,0x74,0x3a,0x20,0x4d,0x6f,0x7a,
        0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,
        0x20,0x28,0x58,0x31,0x31,0x3b,0x20,0x55,
        0x3b,0x20,0x4c,0x69,0x6e,0x75,0x78,0x20,
        0x78,0x38,0x36,0x5f,0x36,0x34,0x3b,0x20,
        0x65,0x6e,0x2d,0x55,0x53,0x3b,0x20,0x72,
        0x76,0x3a,0x31,0x2e,0x39,0x2e,0x30,0x2e,
        0x31,0x34,0x29,0x20,0x47,0x65,0x63,0x6b,
        0x6f,0x2f,0x32,0x30,0x30,0x39,0x30,0x39,
        0x30,0x32,0x31,0x37,0x20,0x55,0x62,0x75,
        0x6e,0x74,0x75,0x2f,0x39,0x2e,0x30,0x34,
        0x20,0x28,0x6a,0x61,0x75,0x6e,0x74,0x79,
        0x29,0x20,0x46,0x69,0x72,0x65,0x66,0x6f,
        0x78,0x2f,0x33,0x2e,0x30,0x2e,0x31,0x34,
        0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,0x74,
        0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,
        0x74,0x6d,0x6c,0x2c,0x61,0x70,0x70,0x6c,
        0x69,0x63,0x61,0x74,0x69,0x6f,0x6e,0x2f,
        0x78,0x68,0x74,0x6d,0x6c,0x2b,0x78,0x6d,
        0x6c,0x2c,0x61,0x70,0x70,0x6c,0x69,0x63,
        0x61,0x74,0x69,0x6f,0x6e,0x2f,0x78,0x6d,
        0x6c,0x3b,0x71,0x3d,0x30,0x2e,0x39,0x2c,
        0x2a,0x2f,0x2a,0x3b,0x71,0x3d,0x30,0x2e,
        0x38,0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,
        0x74,0x2d,0x4c,0x61,0x6e,0x67,0x75,0x61,
        0x67,0x65,0x3a,0x20,0x65,0x6e,0x2d,0x75,
        0x73,0x2c,0x65,0x6e,0x3b,0x71,0x3d,0x30,
        0x2e,0x35,0x0d,0x0a,0x41,0x63,0x63,0x65,
        0x70,0x74,0x2d,0x45,0x6e,0x63,0x6f,0x64,
        0x69,0x6e,0x67,0x3a,0x20,0x67,0x7a,0x69,
        0x70,0x2c,0x64,0x65,0x66,0x6c,0x61,0x74,
        0x65,0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,
        0x74,0x2d,0x43,0x68,0x61,0x72,0x73,0x65,
        0x74,0x3a,0x20,0x49,0x53,0x4f,0x2d,0x38,
        0x38,0x35,0x39,0x2d,0x31,0x2c,0x75,0x74,
        0x66,0x2d,0x38,0x3b,0x71,0x3d,0x30,0x2e,
        0x37,0x2c,0x2a,0x3b,0x71,0x3d,0x30,0x2e,
        0x37,0x0d,0x0a,0x4b,0x65,0x65,0x70,0x2d,
        0x41,0x6c,0x69,0x76,0x65,0x3a,0x20,0x33,
        0x30,0x30,0x0d,0x0a,0x43,0x6f,0x6e,0x6e,
        0x65,0x63,0x74,0x69,0x6f,0x6e,0x3a,0x20,
        0x6b,0x65,0x65,0x70,0x2d,0x61,0x6c,0x69,
        0x76,0x65,0x0d,0x0a,0x0d,0x0a };
        /* end raw_eth_pkt */

    return PortTestMatchReal(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt),
                             sig, sid);
}

/**
 * \test Check if we match a dest port
 */
int PortTestMatchReal01()
{
    /* tcp.sport=47370 tcp.dport=80 */
    char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\"; content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match a source port
 */
int PortTestMatchReal02()
{
    char *sig = "alert tcp any 47370 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match both of them
 */
int PortTestMatchReal03()
{
    char *sig = "alert tcp any 47370 -> any 80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we negate dest ports correctly
 */
int PortTestMatchReal04()
{
    char *sig = "alert tcp any any -> any !80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate source ports correctly
 */
int PortTestMatchReal05()
{
    char *sig = "alert tcp any !47370 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate both ports correctly
 */
int PortTestMatchReal06()
{
    char *sig = "alert tcp any !47370 -> any !80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we match a dest port range
 */
int PortTestMatchReal07()
{
    char *sig = "alert tcp any any -> any 70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match a source port range
 */
int PortTestMatchReal08()
{
    char *sig = "alert tcp any 47000:50000 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match both port ranges
 */
int PortTestMatchReal09()
{
    char *sig = "alert tcp any 47000:50000 -> any 70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we negate a dest port range
 */
int PortTestMatchReal10()
{
    char *sig = "alert tcp any any -> any !70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate a source port range
 */
int PortTestMatchReal11()
{
    char *sig = "alert tcp any !47000:50000 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate both port ranges
 */
int PortTestMatchReal12()
{
    char *sig = "alert tcp any !47000:50000 -> any !70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we autocomplete ranges correctly
 */
int PortTestMatchReal13()
{
    char *sig = "alert tcp any 47000:50000 -> any !81: (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we autocomplete ranges correctly
 */
int PortTestMatchReal14()
{
    char *sig = "alert tcp any !48000:50000 -> any :100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we autocomplete ranges correctly
 */
int PortTestMatchReal15()
{
    char *sig = "alert tcp any :50000 -> any 81:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we separate ranges correctly
 */
int PortTestMatchReal16()
{
    char *sig = "alert tcp any 100: -> any ![0:79,81:65535] (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we separate ranges correctly
 */
int PortTestMatchReal17()
{
    char *sig = "alert tcp any ![0:39999,48000:50000] -> any ![0:80,82:65535] "
                "(msg:\"Nothing..\"; content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we separate ranges correctly
 */
int PortTestMatchReal18()
{
    char *sig = "alert tcp any ![0:39999,48000:50000] -> any 80 (msg:\"Nothing"
                " at all\"; content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we separate ranges correctly
 */
int PortTestMatchReal19()
{
    char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

static int PortTestMatchDoubleNegation(void)
{
    int result = 0;
    DetectPort *head = NULL, *nhead = NULL;

    if (DetectPortParseDo(NULL, &head, &nhead, "![!80]", 0) == -1)
        return result;

    result = (head != NULL);
    result = (nhead == NULL);

    return result;
}

#endif /* UNITTESTS */

void DetectPortTests(void)
{
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
    UtRegisterTest("PortTestParse14", PortTestParse14, 1);
    UtRegisterTest("PortTestParse15", PortTestParse15, 1);
    UtRegisterTest("PortTestParse16", PortTestParse16, 1);
    UtRegisterTest("PortTestFunctions01", PortTestFunctions01, 1);
    UtRegisterTest("PortTestFunctions02", PortTestFunctions02, 1);
    UtRegisterTest("PortTestFunctions03", PortTestFunctions03, 1);
    UtRegisterTest("PortTestFunctions04", PortTestFunctions04, 1);
    UtRegisterTest("PortTestFunctions05", PortTestFunctions05, 1);
    UtRegisterTest("PortTestFunctions06", PortTestFunctions06, 1);
    UtRegisterTest("PortTestMatchReal01", PortTestMatchReal01, 1);
    UtRegisterTest("PortTestMatchReal02", PortTestMatchReal02, 1);
    UtRegisterTest("PortTestMatchReal03", PortTestMatchReal03, 1);
    UtRegisterTest("PortTestMatchReal04", PortTestMatchReal04, 1);
    UtRegisterTest("PortTestMatchReal05", PortTestMatchReal05, 1);
    UtRegisterTest("PortTestMatchReal06", PortTestMatchReal06, 1);
    UtRegisterTest("PortTestMatchReal07", PortTestMatchReal07, 1);
    UtRegisterTest("PortTestMatchReal08", PortTestMatchReal08, 1);
    UtRegisterTest("PortTestMatchReal09", PortTestMatchReal09, 1);
    UtRegisterTest("PortTestMatchReal10", PortTestMatchReal10, 1);
    UtRegisterTest("PortTestMatchReal11", PortTestMatchReal11, 1);
    UtRegisterTest("PortTestMatchReal12", PortTestMatchReal12, 1);
    UtRegisterTest("PortTestMatchReal13", PortTestMatchReal13, 1);
    UtRegisterTest("PortTestMatchReal14", PortTestMatchReal14, 1);
    UtRegisterTest("PortTestMatchReal15", PortTestMatchReal15, 1);
    UtRegisterTest("PortTestMatchReal16", PortTestMatchReal16, 1);
    UtRegisterTest("PortTestMatchReal17", PortTestMatchReal17, 1);
    UtRegisterTest("PortTestMatchReal18", PortTestMatchReal18, 1);
    UtRegisterTest("PortTestMatchReal19",
                   PortTestMatchReal19, 1);
    UtRegisterTest("PortTestMatchDoubleNegation", PortTestMatchDoubleNegation, 1);


#endif /* UNITTESTS */
}

