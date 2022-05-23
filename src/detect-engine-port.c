/* Copyright (C) 2007-2019 Open Information Security Foundation
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
#include "util-var.h"
#include "util-byte.h"

static int DetectPortCutNot(DetectPort *, DetectPort **);
static int DetectPortCut(DetectEngineCtx *, DetectPort *, DetectPort *,
                         DetectPort **);
DetectPort *PortParse(const char *str);
static bool DetectPortIsValidRange(char *, uint16_t *);

/**
 * \brief Alloc a DetectPort structure and update counters
 *
 * \retval dp newly created DetectPort on success; or NULL in case of error.
 */
static DetectPort *DetectPortInit(void)
{
    DetectPort *dp = SCCalloc(1, sizeof(DetectPort));
    if (unlikely(dp == NULL))
        return NULL;
    return dp;
}

/**
 * \brief Free a DetectPort and its members
 *
 * \param dp Pointer to the DetectPort that has to be freed.
 */
void DetectPortFree(const DetectEngineCtx *de_ctx, DetectPort *dp)
{
    if (dp == NULL)
        return;

    /* only free the head if we have the original */
    if (dp->sh != NULL && !(dp->flags & PORT_SIGGROUPHEAD_COPY)) {
        SigGroupHeadFree(de_ctx, dp->sh);
    }
    dp->sh = NULL;

    SCFree(dp);
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
void DetectPortCleanupList (const DetectEngineCtx *de_ctx, DetectPort *head)
{
    if (head == NULL)
        return;

    DetectPort *cur, *next;

    for (cur = head; cur != NULL; ) {
        next = cur->next;
        cur->next = NULL;
        DetectPortFree(de_ctx, cur);
        cur = next;
    }
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
 *
 * \todo rewrite to avoid recursive calls
 * */
int DetectPortInsert(DetectEngineCtx *de_ctx, DetectPort **head,
                     DetectPort *new)
{
    if (new == NULL)
        return 0;

    //BUG_ON(new->next != NULL);
    //BUG_ON(new->prev != NULL);

    /* see if it already exists or overlaps with existing ports */
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
                    DetectPortFree(de_ctx, new);
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
                if (r == -1) {
                    if (c != NULL) {
                        DetectPortFree(de_ctx, c);
                    }
                    goto error;
                }

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

    /* default to NULL */
    *c = NULL;

    int r = DetectPortCmp(a,b);
    BUG_ON(r != PORT_ES && r != PORT_EB && r != PORT_LE && r != PORT_GE);

    /* get a place to temporary put sigs lists */
    DetectPort *tmp = DetectPortInit();
    if (tmp == NULL) {
        goto error;
    }

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

        DetectPort *tmp_c = DetectPortInit();
        if (tmp_c == NULL) {
            goto error;
        }
        *c = tmp_c;

        tmp_c->port = a_port2 + 1;
        tmp_c->port2 = b_port2;

        SigGroupHeadCopySigs(de_ctx,b->sh,&tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh); /* copy a to b */

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

        DetectPort *tmp_c = DetectPortInit();
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
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            SigGroupHeadClearSigs(a->sh); /* clean a list */
            SigGroupHeadCopySigs(de_ctx,tmp->sh,&a->sh);/* merge old a with b */
            SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */
        } else {
            SCLogDebug("3");
            a->port = b_port1;
            a->port2 = a_port1 - 1;

            b->port = a_port1;
            b->port2 = a_port2;

            DetectPort *tmp_c = DetectPortInit();
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

        } else if (a_port2 == b_port2) {
            SCLogDebug("2");

            a->port = a_port1;
            a->port2 = b_port1 - 1;

            b->port = b_port1;
            b->port2 = b_port2;

            /** 'a' overlaps 'b' so 'b' needs the 'a' sigs */
            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);

        } else {
            SCLogDebug("3");
            a->port = a_port1;
            a->port2 = b_port1 - 1;

            b->port = b_port1;
            b->port2 = b_port2;

            DetectPort *tmp_c = DetectPortInit();
            if (tmp_c == NULL) {
                goto error;
            }
            *c = tmp_c;

            tmp_c->port = b_port2 + 1;
            tmp_c->port2 = a_port2;

            SigGroupHeadCopySigs(de_ctx,a->sh,&b->sh);
            SigGroupHeadCopySigs(de_ctx,a->sh,&tmp_c->sh);
        }
    }

    if (tmp != NULL) {
        DetectPortFree(de_ctx, tmp);
    }
    return 0;

error:
    if (tmp != NULL)
        DetectPortFree(de_ctx, tmp);
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
            return -1;
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
        return -1;
    }

    return 0;
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
        return NULL;
    }

    dst->port = src->port;
    dst->port2 = src->port2;

    SigGroupHeadCopySigs(de_ctx,src->sh,&dst->sh);
    return dst;
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
static int DetectPortMatch(DetectPort *dp, uint16_t port)
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
DetectPort *DetectPortLookupGroup(DetectPort *dp, uint16_t port)
{
    if (dp == NULL)
        return NULL;

    for (DetectPort *p = dp; p != NULL; p = p->next) {
        if (DetectPortMatch(p, port) == 1) {
            //SCLogDebug("match, port %" PRIu32 ", dp ", port);
            //DetectPortPrint(p); SCLogDebug("");
            return p;
        }
    }

    return NULL;
}

/**
 * \brief Checks if two port group lists are equal.
 *
 * \param list1 Pointer to the first port group list.
 * \param list2 Pointer to the second port group list.
 *
 * \retval true On success.
 * \retval false On failure.
 */
bool DetectPortListsAreEqual(DetectPort *list1, DetectPort *list2)
{
    DetectPort *item = list1;
    DetectPort *it = list2;

    // First, compare items one by one.
    while (item != NULL && it != NULL) {
        if (DetectPortCmp(item, it) != PORT_EQ) {
            return false;
        }

        item = item->next;
        it = it->next;
    }

    // Are the lists of the same size?
    if (!(item == NULL && it == NULL)) {
        return false;
    }

    return true;
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
static int DetectPortParseInsertString(const DetectEngineCtx *de_ctx,
        DetectPort **head, const char *s)
{
    DetectPort *ad = NULL, *ad_any = NULL;
    int r = 0;
    bool port_any = false;

    SCLogDebug("head %p, *head %p, s %s", head, *head, s);

    /** parse the address */
    ad = PortParse(s);
    if (ad == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT," failed to parse port \"%s\"",s);
        return -1;
    }

    if (ad->flags & PORT_FLAG_ANY) {
        port_any = true;
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
    if (r == 1 && port_any) {
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
        DetectPortCleanupList(de_ctx, ad);
    if (ad_any != NULL)
        DetectPortCleanupList(de_ctx, ad_any);
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
 * \param negate Flag that indicates if the received address string is negated
 *               or not.  0 if it is not, 1 it it is.
 *
 * \retval  0 On successfully parsing.
 * \retval -1 On failure.
 */
static int DetectPortParseDo(const DetectEngineCtx *de_ctx,
                             DetectPort **head, DetectPort **nhead,
                             const char *s, int negate,
                             ResolvedVariablesList *var_list, int recur)
{
    size_t u = 0;
    size_t x = 0;
    int o_set = 0, n_set = 0, d_set = 0;
    int range = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[1024] = "";
    const char *rule_var_port = NULL;
    int r = 0;

    if (recur++ > 64) {
        SCLogError(SC_ERR_PORT_ENGINE_GENERIC, "port block recursion "
                "limit reached (max 64)");
        goto error;
    }

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

                r = DetectPortParseDo(de_ctx, head, nhead, address,
                        negate? negate: n_set, var_list, recur);
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
                if (negate == 1 || n_set == 1) {
                    alloc_rule_var_port = SCMalloc(strlen(rule_var_port) + 3);
                    if (unlikely(alloc_rule_var_port == NULL))
                        goto error;
                    snprintf(alloc_rule_var_port, strlen(rule_var_port) + 3,
                             "[%s]", rule_var_port);
                } else {
                    alloc_rule_var_port = SCStrdup(rule_var_port);
                    if (unlikely(alloc_rule_var_port == NULL))
                        goto error;
                }
                temp_rule_var_port = alloc_rule_var_port;
                r = DetectPortParseDo(de_ctx, head, nhead, temp_rule_var_port,
                                  (negate + n_set) % 2, var_list, recur);
                if (r == -1) {
                    SCFree(alloc_rule_var_port);
                    goto error;
                }
                d_set = 0;
                n_set = 0;
                SCFree(alloc_rule_var_port);
            } else {
                address[x - 1] = '\0';
                SCLogDebug("Parsed port from DetectPortParseDo - %s", address);

                if (negate == 0 && n_set == 0) {
                    r = DetectPortParseInsertString(de_ctx, head, address);
                } else {
                    r = DetectPortParseInsertString(de_ctx, nhead, address);
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

            if (AddVariableToResolveList(var_list, address) == -1) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Found a loop in a port "
                   "groups declaration. This is likely a misconfiguration.");
                goto error;
            }

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
                if ((negate + n_set) % 2) {
                    alloc_rule_var_port = SCMalloc(strlen(rule_var_port) + 3);
                    if (unlikely(alloc_rule_var_port == NULL))
                        goto error;
                    snprintf(alloc_rule_var_port, strlen(rule_var_port) + 3,
                            "[%s]", rule_var_port);
                } else {
                    alloc_rule_var_port = SCStrdup(rule_var_port);
                    if (unlikely(alloc_rule_var_port == NULL))
                        goto error;
                }
                temp_rule_var_port = alloc_rule_var_port;
                r = DetectPortParseDo(de_ctx, head, nhead, temp_rule_var_port,
                                  (negate + n_set) % 2, var_list, recur);
                SCFree(alloc_rule_var_port);
                if (r == -1)
                    goto error;

                d_set = 0;
            } else {
                if (!((negate + n_set) % 2)) {
                    r = DetectPortParseInsertString(de_ctx, head,address);
                } else {
                    r = DetectPortParseInsertString(de_ctx, nhead,address);
                }
                if (r == -1)
                    goto error;
            }
            n_set = 0;
        } else if (depth == 1 && s[u] == ',') {
            range = 0;
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
static int DetectPortIsCompletePortSpace(DetectPort *p)
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
static int DetectPortParseMergeNotPorts(const DetectEngineCtx *de_ctx,
        DetectPort **head, DetectPort **nhead)
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
        r = DetectPortParseInsertString(de_ctx, head,"0:65535");
        if (r < 0) {
            goto error;
        }
    }

    /** step 1: insert our ghn members into the gh list */
    for (ag = *nhead; ag != NULL; ag = ag->next) {
        /** work with a copy of the ad so we can easily clean up
         * the ghn group later.
         */
        ad = DetectPortCopySingle(NULL, ag);
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
                DetectPortFree(de_ctx,ag2);
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
        DetectPortFree(de_ctx, ad);
    return -1;
}

int DetectPortTestConfVars(void)
{
    SCLogDebug("Testing port conf vars for any misconfigured values");

    ResolvedVariablesList var_list = TAILQ_HEAD_INITIALIZER(var_list);

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
            DetectPortCleanupList(NULL, gh);
            goto error;
        }

        int r = DetectPortParseDo(NULL, &gh, &ghn, seq_node->val,
                /* start with negate no */0, &var_list, 0);

        CleanVariableResolveList(&var_list);

        if (r < 0) {
            DetectPortCleanupList(NULL, gh);
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                    "failed to parse port var \"%s\" with value \"%s\". "
                    "Please check its syntax",
                    seq_node->name, seq_node->val);
            goto error;
        }

        if (DetectPortIsCompletePortSpace(ghn)) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                    "Port var - \"%s\" has the complete Port range negated "
                    "with its value \"%s\".  Port space range is NIL. "
                    "Probably have a !any or a port range that supplies "
                    "a NULL address range",
                    seq_node->name, seq_node->val);
            DetectPortCleanupList(NULL, gh);
            DetectPortCleanupList(NULL, ghn);
            goto error;
        }

        if (gh != NULL)
            DetectPortCleanupList(NULL, gh);
        if (ghn != NULL)
            DetectPortCleanupList(NULL, ghn);
    }

    return 0;
 error:
    return -1;
}


/**
 * \brief Function for parsing port strings
 *
 * \param de_ctx Pointer to the detection engine context
 * \param head Pointer to the head of the DetectPort group list
 * \param str Pointer to the port string
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int DetectPortParse(const DetectEngineCtx *de_ctx,
                    DetectPort **head, const char *str)
{
    SCLogDebug("Port string to be parsed - str %s", str);

    /* negate port list */
    DetectPort *nhead = NULL;

    int r = DetectPortParseDo(de_ctx, head, &nhead, str,
            /* start with negate no */ 0, NULL, 0);
    if (r < 0)
        goto error;

    SCLogDebug("head %p %p, nhead %p", head, *head, nhead);

    /* merge the 'not' address groups */
    if (DetectPortParseMergeNotPorts(de_ctx, head, &nhead) < 0)
        goto error;

    /* free the temp negate head */
    DetectPortCleanupList(de_ctx, nhead);
    return 0;

error:
    DetectPortCleanupList(de_ctx, nhead);
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
DetectPort *PortParse(const char *str)
{
    char *port2 = NULL;
    char portstr[16];
    strlcpy(portstr, str, sizeof(portstr));

    DetectPort *dp = DetectPortInit();
    if (dp == NULL)
        goto error;

    // Bug fix for strlen(str) >= 16
    if (strnlen(str, 16) == 16) {
        goto error;
    }

    /* XXX better input validation */

    /* we dup so we can put a nul-termination in it later */
    char *port = portstr;

    /* handle the negation case */
    if (port[0] == '!') {
        dp->flags |= PORT_FLAG_NOT;
        port++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((port2 = strchr(port, ':')) != NULL) {
        /* 80:81 range format */
        port2[0] = '\0';
        port2++;

        if (strcmp(port, "") != 0) {
            if (!DetectPortIsValidRange(port, &dp->port))
                goto error;
        } else {
            dp->port = 0;
        }

        if (strcmp(port2, "") != 0) {
            if (!DetectPortIsValidRange(port2, &dp->port2))
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
        } else {
            if (!DetectPortIsValidRange(port, &dp->port))
                goto error;
            dp->port2 = dp->port;
        }
    }

    return dp;

error:
    if (dp != NULL)
        DetectPortCleanupList(NULL, dp);
    return NULL;
}

/**
 * \brief Helper function to check if a parsed port is in the valid range
 *        of available ports
 *
 * \param str Pointer to the port string
 *
 *
 * \retval true if port is in the valid range
 * \retval false if invalid
 */
static bool DetectPortIsValidRange(char *port, uint16_t *port_val)
{
    if (StringParseUint16(port_val, 10, 0, (const char *)port) < 0)
        return false;

    return true;
}

/********************** End parsing routines ********************/

/* hash table */

/**
 * \brief The hash function to be the used by the hash table -
 *        DetectEngineCtx->dport_hash_table.
 *
 * \param ht      Pointer to the hash table.
 * \param data    Pointer to the DetectPort.
 * \param datalen Not used in our case.
 *
 * \retval hash The generated hash value.
 */
static uint32_t DetectPortHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    DetectPort *p = (DetectPort *)data;
    SCLogDebug("hashing port %p", p);

    uint32_t hash = ((uint32_t)p->port << 16) | p->port2;

    hash %= ht->array_size;
    SCLogDebug("hash %"PRIu32, hash);
    return hash;
}

/**
 * \brief The Compare function to be used by the DetectPort hash table -
 *        DetectEngineCtx->dport_hash_table.
 *
 * \param data1 Pointer to the first DetectPort.
 * \param len1  Not used.
 * \param data2 Pointer to the second DetectPort.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 DetectPort sent as args match.
 * \retval 0 If the 2 DetectPort sent as args do not match.
 */
static char DetectPortCompareFunc(void *data1, uint16_t len1,
                                  void *data2, uint16_t len2)
{
    DetectPort *dp1 = (DetectPort *)data1;
    DetectPort *dp2 = (DetectPort *)data2;

    if (data1 == NULL || data2 == NULL)
        return 0;

    if (dp1->port == dp2->port && dp1->port2 == dp2->port2)
        return 1;

    return 0;
}

static void DetectPortHashFreeFunc(void *ptr)
{
    DetectPort *p = ptr;
    DetectPortFree(NULL, p);
}

/**
 * \brief Initializes the hash table in the detection engine context to hold the
 *        DetectPort hash.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectPortHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->dport_hash_table = HashListTableInit(4096, DetectPortHashFunc,
                                                       DetectPortCompareFunc,
                                                       DetectPortHashFreeFunc);
    if (de_ctx->dport_hash_table == NULL)
        return -1;

    return 0;
}

/**
 * \brief Adds a DetectPort to the detection engine context DetectPort
 *        hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param dp     Pointer to the DetectPort.
 *
 * \retval ret 0 on Successfully adding the DetectPort; -1 on failure.
 */
int DetectPortHashAdd(DetectEngineCtx *de_ctx, DetectPort *dp)
{
    int ret = HashListTableAdd(de_ctx->dport_hash_table, (void *)dp, 0);
    return ret;
}

/**
 * \brief Used to lookup a DetectPort hash from the detection engine context
 *        DetectPort hash table.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the DetectPort.
 *
 * \retval rsgh On success a pointer to the DetectPort if the DetectPort is
 *              found in the hash table; NULL on failure.
 */
DetectPort *DetectPortHashLookup(DetectEngineCtx *de_ctx, DetectPort *dp)
{
    SCEnter();

    DetectPort *rdp = HashListTableLookup(de_ctx->dport_hash_table, (void *)dp, 0);

    SCReturnPtr(rdp, "DetectPort");
}

/**
 * \brief Frees the hash table - DetectEngineCtx->sgh_hash_table, allocated by
 *        DetectPortInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void DetectPortHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->sgh_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->dport_hash_table);
    de_ctx->dport_hash_table = NULL;

    return;
}

/*---------------------- Unittests -------------------------*/

#ifdef UNITTESTS
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
static int PortTestDetectPortAdd(DetectPort **head, DetectPort *dp)
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
 * \test Check if a DetectPort is properly allocated
 */
static int PortTestParse01 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"80");
    FAIL_IF_NOT(r == 0);
    DetectPortFree(NULL, dd);
    PASS;
}

/**
 * \test Check if two ports are properly allocated in the DetectPort group
 */
static int PortTestParse02 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"80");
    FAIL_IF_NOT(r == 0);
    r = DetectPortParse(NULL,&dd,"22");
    FAIL_IF_NOT(r == 0);
    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Check if two port ranges are properly allocated in the DetectPort group
 */
static int PortTestParse03 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"80:88");
    FAIL_IF_NOT(r == 0);
    r = DetectPortParse(NULL,&dd,"85:100");
    FAIL_IF_NOT(r == 0);
    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Check if a negated port range is properly allocated in the DetectPort
 */
static int PortTestParse04 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"!80:81");
    FAIL_IF_NOT(r == 0);
    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Check if a negated port range is properly fragmented in the allowed
 *       real groups, ex !80:81 should allow 0:79 and 82:65535
 */
static int PortTestParse05 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"!80:81");
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(dd->next);
    FAIL_IF_NOT(dd->port == 0);
    FAIL_IF_NOT(dd->port2 == 79);
    FAIL_IF_NOT(dd->next->port == 82);
    FAIL_IF_NOT(dd->next->port2 == 65535);
    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Check if a negated port range is properly fragmented in the allowed
 *       real groups
 */
static int PortTestParse07 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"!21:902");
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(dd->next);

    FAIL_IF_NOT(dd->port == 0);
    FAIL_IF_NOT(dd->port2 == 20);
    FAIL_IF_NOT(dd->next->port == 903);
    FAIL_IF_NOT(dd->next->port2 == 65535);

    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Check if we dont allow invalid port range specification
 */
static int PortTestParse08 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"[80:!80]");
    FAIL_IF(r == 0);

    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Check if we autocomplete correctly an open range
 */
static int PortTestParse09 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"1024:");
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(dd);

    FAIL_IF_NOT(dd->port == 1024);
    FAIL_IF_NOT(dd->port2 == 0xffff);

    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Test we don't allow a port that is too big
 */
static int PortTestParse10 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"77777777777777777777777777777777777777777777");
    FAIL_IF(r == 0);
    PASS;
}

/**
 * \test Test second port of range being too big
 */
static int PortTestParse11 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"1024:65536");
    FAIL_IF(r == 0);
    PASS;
}

/**
 * \test Test second port of range being just right
 */
static int PortTestParse12 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"1024:65535");
    FAIL_IF_NOT(r == 0);
    DetectPortFree(NULL, dd);
    PASS;
}

/**
 * \test Test first port of range being too big
 */
static int PortTestParse13 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"65536:65535");
    FAIL_IF(r == 0);
    PASS;
}

/**
 * \test Test merging port groups
 */
static int PortTestParse14 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParseInsertString(NULL, &dd, "0:100");
    FAIL_IF_NOT(r == 0);
    r = DetectPortParseInsertString(NULL, &dd, "1000:65535");
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(dd->next);

    FAIL_IF_NOT(dd->port == 0);
    FAIL_IF_NOT(dd->port2 == 100);
    FAIL_IF_NOT(dd->next->port == 1000);
    FAIL_IF_NOT(dd->next->port2 == 65535);

    DetectPortCleanupList(NULL, dd);
    PASS;
}

/**
 * \test Test merging negated port groups
 */
static int PortTestParse15 (void)
{
    DetectPort *dd = NULL;

    int r = DetectPortParse(NULL,&dd,"![0:100,1000:3000]");
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(dd->next);

    FAIL_IF_NOT(dd->port == 101);
    FAIL_IF_NOT(dd->port2 == 999);
    FAIL_IF_NOT(dd->next->port == 3001);
    FAIL_IF_NOT(dd->next->port2 == 65535);

    DetectPortCleanupList(NULL, dd);
    PASS;
}

static int PortTestParse16 (void)
{
    DetectPort *dd = NULL;
    int r = DetectPortParse(NULL,&dd,"\
[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\
1:65535\
]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]\
");
    FAIL_IF_NOT(r == 0);
    DetectPortFree(NULL, dd);
    dd = NULL;
    r = DetectPortParse(NULL,&dd,"\
[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\
1:65535\
]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]\
");
    FAIL_IF(r == 0);
    PASS;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions01(void)
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
    r = PortTestDetectPortAdd(&head, dp1);
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
        DetectPortFree(NULL, dp1);
    if (head != NULL)
        DetectPortFree(NULL, head);
    return result;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions02(void)
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
    r = DetectPortParseMergeNotPorts(NULL, &head, &dp1);
    if (r != 0 || head->next != NULL)
        goto end;

    r = DetectPortParse(NULL, &dp2, "!100:500");
    if (r != 0 || dp2->next == NULL)
        goto end;

    /* Merge Nots */
    r = DetectPortParseMergeNotPorts(NULL, &head, &dp2);
    if (r != 0 || head->next != NULL)
        goto end;

    if (!(head->port == 200))
        goto end;
    if (!(head->port2 == 300))
        goto end;

    result = 1;

end:
    if (dp1 != NULL)
        DetectPortFree(NULL, dp1);
    if (dp2 != NULL)
        DetectPortFree(NULL, dp2);
    if (head != NULL)
        DetectPortFree(NULL, head);
    return result;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions03(void)
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
        DetectPortFree(NULL, dp1);
    if (dp2 != NULL)
        DetectPortFree(NULL, dp2);
    if (dp3 != NULL)
        DetectPortFree(NULL, dp3);
    return result;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions04(void)
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
        DetectPortFree(NULL, dp1);
    if (dp2 != NULL)
        DetectPortFree(NULL, dp2);
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
        DetectPortFree(NULL, dp1);
    if (dp2 != NULL)
        DetectPortFree(NULL, dp2);
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
        DetectPortFree(NULL, dp1);
    if (dp2 != NULL)
        DetectPortFree(NULL, dp2);
    return result;
}

/**
 * \test Test general functions
 */
static int PortTestFunctions07(void)
{
    DetectPort *dd = NULL;

    // This one should fail due to negation in a range
    FAIL_IF(DetectPortParse(NULL, &dd, "[80:!99]") == 0);

    // Correct: from 80 till 100 but 99 excluded
    FAIL_IF_NOT(DetectPortParse(NULL, &dd, "[80:100,!99]") == 0);
    FAIL_IF_NULL(dd->next);
    FAIL_IF_NOT(dd->port == 80);
    FAIL_IF_NOT(dd->port2 == 98);
    FAIL_IF_NOT(dd->next->port == 100);

    // Also good: from 1 till 80 except of 2 and 4
    FAIL_IF_NOT(DetectPortParse(NULL, &dd, "[1:80,![2,4]]") == 0);
    FAIL_IF_NOT(dd->port == 1);
    FAIL_IF_NULL(DetectPortLookupGroup(dd, 3));
    FAIL_IF_NOT_NULL(DetectPortLookupGroup(dd, 2));
    FAIL_IF_NULL(DetectPortLookupGroup(dd, 80));

    DetectPortCleanupList(NULL, dd);
    PASS;
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
static int PortTestMatchReal(uint8_t *raw_eth_pkt, uint16_t pktsize, const char *sig,
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
static int PortTestMatchRealWrp(const char *sig, uint32_t sid)
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
static int PortTestMatchReal01(void)
{
    /* tcp.sport=47370 tcp.dport=80 */
    const char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\"; content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match a source port
 */
static int PortTestMatchReal02(void)
{
    const char *sig = "alert tcp any 47370 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match both of them
 */
static int PortTestMatchReal03(void)
{
    const char *sig = "alert tcp any 47370 -> any 80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we negate dest ports correctly
 */
static int PortTestMatchReal04(void)
{
    const char *sig = "alert tcp any any -> any !80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate source ports correctly
 */
static int PortTestMatchReal05(void)
{
    const char *sig = "alert tcp any !47370 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate both ports correctly
 */
static int PortTestMatchReal06(void)
{
    const char *sig = "alert tcp any !47370 -> any !80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we match a dest port range
 */
static int PortTestMatchReal07(void)
{
    const char *sig = "alert tcp any any -> any 70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match a source port range
 */
static int PortTestMatchReal08(void)
{
    const char *sig = "alert tcp any 47000:50000 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we match both port ranges
 */
static int PortTestMatchReal09(void)
{
    const char *sig = "alert tcp any 47000:50000 -> any 70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we negate a dest port range
 */
static int PortTestMatchReal10(void)
{
    const char *sig = "alert tcp any any -> any !70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate a source port range
 */
static int PortTestMatchReal11(void)
{
    const char *sig = "alert tcp any !47000:50000 -> any any (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we negate both port ranges
 */
static int PortTestMatchReal12(void)
{
    const char *sig = "alert tcp any !47000:50000 -> any !70:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we autocomplete ranges correctly
 */
static int PortTestMatchReal13(void)
{
    const char *sig = "alert tcp any 47000:50000 -> any !81: (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we autocomplete ranges correctly
 */
static int PortTestMatchReal14(void)
{
    const char *sig = "alert tcp any !48000:50000 -> any :100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we autocomplete ranges correctly
 */
static int PortTestMatchReal15(void)
{
    const char *sig = "alert tcp any :50000 -> any 81:100 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we separate ranges correctly
 */
static int PortTestMatchReal16(void)
{
    const char *sig = "alert tcp any 100: -> any ![0:79,81:65535] (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we separate ranges correctly
 */
static int PortTestMatchReal17(void)
{
    const char *sig = "alert tcp any ![0:39999,48000:50000] -> any ![0:80,82:65535] "
                "(msg:\"Nothing..\"; content:\"GET\"; sid:1;)";
    return (PortTestMatchRealWrp(sig, 1) == 0)? 1 : 0;
}

/**
 * \test Check if we separate ranges correctly
 */
static int PortTestMatchReal18(void)
{
    const char *sig = "alert tcp any ![0:39999,48000:50000] -> any 80 (msg:\"Nothing"
                " at all\"; content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

/**
 * \test Check if we separate ranges correctly
 */
static int PortTestMatchReal19(void)
{
    const char *sig = "alert tcp any any -> any 80 (msg:\"Nothing..\";"
                " content:\"GET\"; sid:1;)";
    return PortTestMatchRealWrp(sig, 1);
}

static int PortTestMatchDoubleNegation(void)
{
    int result = 0;
    DetectPort *head = NULL, *nhead = NULL;

    if (DetectPortParseDo(NULL, &head, &nhead, "![!80]", 0, NULL, 0) == -1)
        return result;

    result = (head != NULL);
    result = (nhead == NULL);

    return result;
}

// Test that negation is successfully parsed with whitespace for port strings of
// length < 16
static int DetectPortParseDoTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectPort *head = NULL;
    DetectPort *nhead = NULL;
    const char *str = "[30:50, !45]";
    int r = DetectPortParseDo(de_ctx, &head, &nhead, str, 0, NULL, 0);

    // Assertions
    FAIL_IF_NULL(head);
    FAIL_IF_NULL(nhead);
    FAIL_IF(r < 0);
    FAIL_IF(head->port != 30);
    FAIL_IF(head->port2 != 50);
    FAIL_IF(nhead->port != 45);
    FAIL_IF(nhead->port2 != 45);
    PASS;
}

// Tests that port strings of length == 16 fail to parse
static int DetectPortParseDoTest2(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectPort *head = NULL;
    DetectPort *nhead = NULL;
    const char *str = "[30:50,              !45]";
    int r = DetectPortParseDo(de_ctx, &head, &nhead, str, 0, NULL, 0);
    FAIL_IF(r >= 0);
    PASS;
}

// Verifies correct parsing when negation port string length < 16
static int PortParseTestLessThan14Spaces(void)
{
    const char *str = "       45";
    DetectPort *dp = NULL;
    dp = PortParse(str);

    FAIL_IF(dp->port != 45);
    FAIL_IF(dp->port2 != 45);
    PASS;
}

// Verifies NULL returned when negation port string length == 16
static int PortParseTest14Spaces(void)
{
    const char *str = "              45";
    DetectPort *dp = NULL;
    dp = PortParse(str);
    FAIL_IF_NOT_NULL(dp);
    PASS;
}

// Verifies NULL returned when negation port string length >= 16
static int PortParseTestMoreThan14Spaces(void)
{
    const char *str = "                                   45";
    DetectPort *dp = NULL;
    dp = PortParse(str);
    FAIL_IF_NOT_NULL(dp);
    PASS;
}

void DetectPortTests(void)
{
    UtRegisterTest("PortTestParse01", PortTestParse01);
    UtRegisterTest("PortTestParse02", PortTestParse02);
    UtRegisterTest("PortTestParse03", PortTestParse03);
    UtRegisterTest("PortTestParse04", PortTestParse04);
    UtRegisterTest("PortTestParse05", PortTestParse05);
    UtRegisterTest("PortTestParse07", PortTestParse07);
    UtRegisterTest("PortTestParse08", PortTestParse08);
    UtRegisterTest("PortTestParse09", PortTestParse09);
    UtRegisterTest("PortTestParse10", PortTestParse10);
    UtRegisterTest("PortTestParse11", PortTestParse11);
    UtRegisterTest("PortTestParse12", PortTestParse12);
    UtRegisterTest("PortTestParse13", PortTestParse13);
    UtRegisterTest("PortTestParse14", PortTestParse14);
    UtRegisterTest("PortTestParse15", PortTestParse15);
    UtRegisterTest("PortTestParse16", PortTestParse16);
    UtRegisterTest("PortTestFunctions01", PortTestFunctions01);
    UtRegisterTest("PortTestFunctions02", PortTestFunctions02);
    UtRegisterTest("PortTestFunctions03", PortTestFunctions03);
    UtRegisterTest("PortTestFunctions04", PortTestFunctions04);
    UtRegisterTest("PortTestFunctions05", PortTestFunctions05);
    UtRegisterTest("PortTestFunctions06", PortTestFunctions06);
    UtRegisterTest("PortTestFunctions07", PortTestFunctions07);
    UtRegisterTest("PortTestMatchReal01", PortTestMatchReal01);
    UtRegisterTest("PortTestMatchReal02", PortTestMatchReal02);
    UtRegisterTest("PortTestMatchReal03", PortTestMatchReal03);
    UtRegisterTest("PortTestMatchReal04", PortTestMatchReal04);
    UtRegisterTest("PortTestMatchReal05", PortTestMatchReal05);
    UtRegisterTest("PortTestMatchReal06", PortTestMatchReal06);
    UtRegisterTest("PortTestMatchReal07", PortTestMatchReal07);
    UtRegisterTest("PortTestMatchReal08", PortTestMatchReal08);
    UtRegisterTest("PortTestMatchReal09", PortTestMatchReal09);
    UtRegisterTest("PortTestMatchReal10", PortTestMatchReal10);
    UtRegisterTest("PortTestMatchReal11", PortTestMatchReal11);
    UtRegisterTest("PortTestMatchReal12", PortTestMatchReal12);
    UtRegisterTest("PortTestMatchReal13", PortTestMatchReal13);
    UtRegisterTest("PortTestMatchReal14", PortTestMatchReal14);
    UtRegisterTest("PortTestMatchReal15", PortTestMatchReal15);
    UtRegisterTest("PortTestMatchReal16", PortTestMatchReal16);
    UtRegisterTest("PortTestMatchReal17", PortTestMatchReal17);
    UtRegisterTest("PortTestMatchReal18", PortTestMatchReal18);
    UtRegisterTest("PortTestMatchReal19", PortTestMatchReal19);
    UtRegisterTest("PortTestMatchDoubleNegation", PortTestMatchDoubleNegation);
    UtRegisterTest("DetectPortParseDoTest", DetectPortParseDoTest);
    UtRegisterTest("DetectPortParseDoTest2", DetectPortParseDoTest2);
    UtRegisterTest("PortParseTestLessThan14Spaces", PortParseTestLessThan14Spaces);
    UtRegisterTest("PortParseTest14Spaces", PortParseTest14Spaces);
    UtRegisterTest("PortParseTestMoreThan14Spaces", PortParseTestMoreThan14Spaces);
}

#endif /* UNITTESTS */

