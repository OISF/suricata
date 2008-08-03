/* Address2 part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * TODO move this out of the detection plugin structure */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

int DetectAddress2Setup (Signature *s, SigMatch *m, char *sidstr);
void DetectAddress2Tests (void);

void DetectAddress2Register (void) {
    sigmatch_table[DETECT_ADDRESS2].name = "address2";
    sigmatch_table[DETECT_ADDRESS2].Match = NULL;
    sigmatch_table[DETECT_ADDRESS2].Setup = DetectAddress2Setup;
    sigmatch_table[DETECT_ADDRESS2].Free = NULL;
    sigmatch_table[DETECT_ADDRESS2].RegisterTests = DetectAddress2Tests;
}

typedef struct DetectAddress2Data_ {
    u_int8_t family;
    u_int32_t ip[4];
    u_int32_t mask[4];
} DetectAddress2Data;

typedef struct DetectAddress2Group_ {
    /* address data for this group */
    DetectAddress2Data *ad;

    /* XXX ptr to rules, or PortGroup or whatever */


    /* double linked list */
    struct DetectAddress2Group_ *prev;
    struct DetectAddress2Group_ *next;

} DetectAddress2Group;

/* list head */
static DetectAddress2Group *head = NULL;

/* prototypes */
DetectAddress2Data *DetectAddress2Parse(char *);
void DetectAddress2DataPrint(DetectAddress2Data *);
void DetectAddress2Free(DetectAddress2Data *);
int Address2Cmp(DetectAddress2Data *, DetectAddress2Data *);


/* a is ... than b */
enum {
    ADDRESS_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    ADDRESS_LT,      /* smaller              [aaa] [bbb] */
    ADDRESS_LE,      /* smaller with overlap [aa[bab]bb] */
    ADDRESS_EQ,      /* exactly equal        [abababab]  */
    ADDRESS_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    ADDRESS_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    ADDRESS_GE,      /* bigger with overlap  [bb[aba]aa] */
    ADDRESS_GT,      /* bigger               [bbb] [aaa] */
};

DetectAddress2Group *DetectAddress2GroupInit(void) {
    DetectAddress2Group *ag = malloc(sizeof(DetectAddress2Group));
    if (ag == NULL) {
        return NULL;
    }
    memset(ag,0,sizeof(DetectAddress2Group));

    return ag;
}

void DetectAddress2GroupFree(DetectAddress2Group *ag) {
    if (ag != NULL) {
        if (ag->ad != NULL) {
            DetectAddress2Free(ag->ad);
        }
        free(ag);
    }
}

void DetectAddress2GroupPrintList(void) {
    DetectAddress2Group *cur;

    printf("list:\n");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             DetectAddress2DataPrint(cur->ad);
        }
    }
    printf("endlist\n");
}

void DetectAddress2GroupCleanupList (void) {
    if (head == NULL)
        return;

    DetectAddress2Group *cur, *next;

    for (cur = head; cur != NULL; ) {
         next = cur->next;

         DetectAddress2GroupFree(cur);
         cur = next;
    }

    head = NULL;
}

int DetectAddress2GroupInsert(DetectAddress2Data *new) {
    DetectAddress2Group *ag = NULL,*cur = NULL;
    int r = 0;

    //printf("DetectAddress2GroupInsert start inserting: ");
    //DetectAddress2DataPrint(new);
    //DetectAddress2GroupPrintList();

    /* see if it already exists or overlaps with existing ag's */
    if (head != NULL) {
        //printf("DetectAddress2GroupInsert we have a head\n");
        for (cur = head; cur != NULL; cur = cur->next) {
            
            //printf("DetectAddress2GroupInsert list: ");
            //DetectAddress2DataPrint(cur->ad);

            r = Address2Cmp(new,cur->ad);
            if (r == ADDRESS_ER) {
                //printf("ADDRESS_ER\n");
                goto error;
            } 
            /* if so, handle that */
            if (r == ADDRESS_EQ) {
                //printf("ADDRESS_EQ\n");
                /* exact overlap/match, we don't need to do a thing
                 */
                return 0;
            } else if (r == ADDRESS_GT) {
                //printf("ADDRESS_GT\n");
                /* only add it now if we are bigger than the last
                 * group. Otherwise we'll handle it later. */
                if (cur->next == NULL) {
                    /* append */
                    ag = DetectAddress2GroupInit();
                    if (ag == NULL) {
                        goto error;
                    }
                    ag->ad = new;

                    /* put in the list */
                    ag->prev = cur;
                    cur->next = ag;
                    return 0;
                }
            } else if (r == ADDRESS_LT) {
                //printf("ADDRESS_LT\n");
                /* see if we need to insert the ag anywhere */

                ag = DetectAddress2GroupInit();
                if (ag == NULL) {
                    goto error;
                }
                ag->ad = new;

                /* put in the list */
                if (cur->prev != NULL)
                    cur->prev->next = ag;
                ag->prev = cur->prev;
                ag->next = cur;
                cur->prev = ag;

                /* update head if required */
                if (head == cur) {
                    head = ag;
                }
                return 0;

            /* alright, those were the simple cases, 
             * lets handle the more complex ones now */

            } else if (r == ADDRESS_ES) {
                DetectAddress2Data *c = NULL;
                r = Address2CutIPv4(cur->ad,new,&c);
                //printf("ADDRESS_ES: r = %d: ", r);
                //DetectAddress2DataPrint(cur->ad);
                DetectAddress2GroupInsert(new);
                if (c) DetectAddress2GroupInsert(c);
            } else if (r == ADDRESS_EB) {
                DetectAddress2Data *c = NULL;
                r = Address2CutIPv4(cur->ad,new,&c);
                //printf("ADDRESS_EB: r = %d: ", r);
                //DetectAddress2DataPrint(cur->ad);
                DetectAddress2GroupInsert(new);
                if (c) DetectAddress2GroupInsert(c);
            } else if (r == ADDRESS_LE) {
                DetectAddress2Data *c = NULL;
                r = Address2CutIPv4(cur->ad,new,&c);
                //printf("ADDRESS_LE: r = %d: ", r);
                //DetectAddress2DataPrint(cur->ad);
                DetectAddress2GroupInsert(new);
                if (c) DetectAddress2GroupInsert(c);
            } else if (r == ADDRESS_GE) {
                DetectAddress2Data *c = NULL;
                r = Address2CutIPv4(cur->ad,new,&c);
                //printf("ADDRESS_GE: r = %d: ", r);
                //DetectAddress2DataPrint(cur->ad);
                DetectAddress2GroupInsert(new);
                if (c) DetectAddress2GroupInsert(c);
            }
        }
    } else {
        //printf("DetectAddress2GroupInsert no head, empty list\n");
        head = ag = DetectAddress2GroupInit();
        if (ag == NULL) {
            goto error;
        }

        ag->ad = new;
    }

    return 0;
error:
    return -1;
}

int DetectAddress2GroupSetup(char *s) {
    DetectAddress2Group *ag = NULL, *cur = NULL, *next = NULL, *prev = NULL;
    DetectAddress2Data  *ad = NULL;
    int r = 0;

    /* parse the address */
    ad = DetectAddress2Parse(s);
    if (ad == NULL) {
        printf("DetectAddress2Parse error \"%s\"\n",s);
        goto error;
    }
    //printf("\n");
    DetectAddress2GroupInsert(ad);
    //DetectAddress2GroupPrintList();
    return 0;

error:
    printf("DetectAddress2GroupSetup error\n");
    /* cleanup */
    return -1;
}

int Address2CmpIPv4(DetectAddress2Data *a, DetectAddress2Data *b) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->mask[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->mask[0]);

    /* ADDRESS_EQ */
    if (a_ip1 == b_ip1 && a_ip2 == b_ip2) {
        //printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    /* ADDRESS_ES */
    } else if (a_ip1 >= b_ip1 && a_ip1 < b_ip2 && a_ip2 <= b_ip2) {
        //printf("ADDRESS_ES\n");
        return ADDRESS_ES;
    /* ADDRESS_EB */
    } else if (a_ip1 <= b_ip1 && a_ip2 >= b_ip2) {
        //printf("ADDRESS_EB\n");
        return ADDRESS_EB;
    } else if (a_ip1 < b_ip1 && a_ip2 < b_ip2 && a_ip2 > b_ip1) {
        //printf("ADDRESS_LE\n");
        return ADDRESS_LE;
    } else if (a_ip1 < b_ip1 && a_ip2 < b_ip2) {
        //printf("ADDRESS_LT\n");
        return ADDRESS_LT;
    } else if (a_ip1 > b_ip1 && a_ip1 < b_ip2 && a_ip2 > b_ip2) {
        //printf("ADDRESS_GE\n");
        return ADDRESS_GE;
    } else if (a_ip1 > b_ip2) {
        //printf("ADDRESS_GT\n");
        return ADDRESS_GT;
    } else {
        /* should be unreachable */
        printf("Internal Error: should be unreachable\n");
    }

    printf("a->ip[0] %u, a->mask[0] %u\n", ntohl(a->ip[0]), ntohl(a->mask[0]));
    DetectAddress2DataPrint(a);
    printf("b->ip[0] %u, b->mask[0] %u\n", ntohl(b->ip[0]), ntohl(b->mask[0]));
    DetectAddress2DataPrint(b);
    printf ("ADDRESS_ER\n");
    return ADDRESS_ER;
}

int Address2CutIPv42(DetectAddress2Data *a, DetectAddress2Data *b) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->mask[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->mask[0]);

    int r = Address2Cmp(a,b);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        goto error;
    }

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    if (r == ADDRESS_LE) {
        a->ip[0]   = htonl(a_ip1);
        a->mask[0] = htonl(b_ip1 - 1);

        b->ip[0]   = htonl(b_ip1);
        b->mask[0] = htonl(b_ip2);
    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */ 
    } else if (r == ADDRESS_GE) {
        a->ip[0]   = htonl(b_ip1);
        a->mask[0] = htonl(a_ip1 - 1);

        b->ip[0]   = htonl(a_ip1);
        b->mask[0] = htonl(a_ip2);
    /* we have 2 or three parts:
     *
     * 2 part: [[abab]bbb] or [bbb[baba]]
     * part a: a_ip1 <-> a_ip2
     * part b: a_ip2 + 1 <-> b_ip2
     *
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> a_ip2
     * 
     * 3 part [bbb[aaa]bbb]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    } else if (r == ADDRESS_ES) {
        if (a_ip1 == b_ip1) {
            a->ip[0]   = htonl(a_ip1);
            a->mask[0] = htonl(a_ip2);

            b->ip[0]   = htonl(a_ip2 + 1);
            b->mask[0] = htonl(b_ip2);
        } else if (a_ip2 == b_ip2) {
            a->ip[0]   = htonl(b_ip1);
            a->mask[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->mask[0] = htonl(a_ip2);
        } else {
            a->ip[0]   = htonl(b_ip1);
            a->mask[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->mask[0] = htonl(b_ip2);
        }
    /* we have 2 or three parts:
     *
     * 2 part: [[baba]aaa] or [aaa[abab]]
     * part a: b_ip1 <-> b_ip2
     * part b: b_ip2 + 1 <-> a_ip2
     *
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> b_ip2
     * 
     * 3 part [aaa[bbb]aaa]
     * part a: a_ip1 <-> b_ip2 - 1
     * part b: b_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_EB) {
        if (a_ip1 == b_ip1) {
            a->ip[0]   = htonl(b_ip1);
            a->mask[0] = htonl(b_ip2);

            b->ip[0]   = htonl(b_ip2 + 1);
            b->mask[0] = htonl(a_ip2);
        } else if (a_ip2 == b_ip2) {
            a->ip[0]   = htonl(a_ip1);
            a->mask[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->mask[0] = htonl(b_ip2);
        } else {
            a->ip[0]   = htonl(a_ip1);
            a->mask[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->mask[0] = htonl(a_ip2);
        }
    }

    return 0;

error:
    return -1;
}

/* a = 1.2.3.4, b = 1.2.3.4-1.2.3.5
 * must result in: a == 1.2.3.4, b == 1.2.3.5, c == NULL
 *
 * a = 1.2.3.4, b = 1.2.3.3-1.2.3.5
 * must result in: a == 1.2.3.3, b == 1.2.3.4, c == 1.2.3.5
 *
 * a = 1.2.3.0/24 b = 1.2.3.128-1.2.4.10
 * must result in: a == 1.2.3.0/24, b == 1.2.4.0-1.2.4.10, c == NULL
 *
 * a = 1.2.3.4, b = 1.2.3.0/24
 * must result in: a == 1.2.3.0-1.2.3.3, b == 1.2.3.4, c == 1.2.3.5-1.2.3.255
 */
int Address2CutIPv4(DetectAddress2Data *a, DetectAddress2Data *b, DetectAddress2Data **c) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->mask[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->mask[0]);

    /* default to NULL */
    *c = NULL;

    int r = Address2Cmp(a,b);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        goto error;
    }

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    if (r == ADDRESS_LE) {
        a->ip[0]   = htonl(a_ip1);
        a->mask[0] = htonl(b_ip1 - 1);

        b->ip[0]   = htonl(b_ip1);
        b->mask[0] = htonl(a_ip2);

        DetectAddress2Data *tmp_c;
        tmp_c = malloc(sizeof(DetectAddress2Data));
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET;
        tmp_c->ip[0]   = htonl(a_ip2 + 1);
        tmp_c->mask[0] = htonl(b_ip2);
        *c = tmp_c;

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */ 
    } else if (r == ADDRESS_GE) {
        a->ip[0]   = htonl(b_ip1);
        a->mask[0] = htonl(a_ip1 - 1);

        b->ip[0]   = htonl(a_ip1);
        b->mask[0] = htonl(b_ip2);

        DetectAddress2Data *tmp_c;
        tmp_c = malloc(sizeof(DetectAddress2Data));
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET;
        tmp_c->ip[0]   = htonl(b_ip2 + 1);
        tmp_c->mask[0] = htonl(a_ip2);
        *c = tmp_c;

    /* we have 2 or three parts:
     *
     * 2 part: [[abab]bbb] or [bbb[baba]]
     * part a: a_ip1 <-> a_ip2
     * part b: a_ip2 + 1 <-> b_ip2
     *
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> a_ip2
     * 
     * 3 part [bbb[aaa]bbb]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    } else if (r == ADDRESS_ES) {
        if (a_ip1 == b_ip1) {
            a->ip[0]   = htonl(a_ip1);
            a->mask[0] = htonl(a_ip2);

            b->ip[0]   = htonl(a_ip2 + 1);
            b->mask[0] = htonl(b_ip2);
        } else if (a_ip2 == b_ip2) {
            a->ip[0]   = htonl(b_ip1);
            a->mask[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->mask[0] = htonl(a_ip2);
        } else {
            a->ip[0]   = htonl(b_ip1);
            a->mask[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->mask[0] = htonl(a_ip2);

            DetectAddress2Data *tmp_c;
            tmp_c = malloc(sizeof(DetectAddress2Data));
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET;
            tmp_c->ip[0]   = htonl(a_ip2 + 1);
            tmp_c->mask[0] = htonl(b_ip2);
            *c = tmp_c;
        }
    /* we have 2 or three parts:
     *
     * 2 part: [[baba]aaa] or [aaa[abab]]
     * part a: b_ip1 <-> b_ip2
     * part b: b_ip2 + 1 <-> a_ip2
     *
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> b_ip2
     * 
     * 3 part [aaa[bbb]aaa]
     * part a: a_ip1 <-> b_ip2 - 1
     * part b: b_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_EB) {
        if (a_ip1 == b_ip1) {
            a->ip[0]   = htonl(b_ip1);
            a->mask[0] = htonl(b_ip2);

            b->ip[0]   = htonl(b_ip2 + 1);
            b->mask[0] = htonl(a_ip2);
        } else if (a_ip2 == b_ip2) {
            a->ip[0]   = htonl(a_ip1);
            a->mask[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->mask[0] = htonl(b_ip2);
        } else {
            a->ip[0]   = htonl(a_ip1);
            a->mask[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->mask[0] = htonl(b_ip2);

            DetectAddress2Data *tmp_c;
            tmp_c = malloc(sizeof(DetectAddress2Data));
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET;
            tmp_c->ip[0]   = htonl(b_ip2 + 1);
            tmp_c->mask[0] = htonl(a_ip2);
            *c = tmp_c;
        }
    }

    return 0;

error:
    return -1;
}


/* return: 1 lt, 0 not lt */
static int Address2IPv6Lt(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] < b[i])
            return 1;
    }

    return 0;
}

/* return: 1 gt, 0 not gt */
static int Address2IPv6Gt(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
    }

    return 0;
}

/* return: 1 eq, 0 not eq */
static int Address2IPv6Eq(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

/* return: 1 le, 0 not le */
static int Address2IPv6Le(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    if (Address2IPv6Eq(a,b) == 1)
        return 1;

    for (i = 0; i < 4; i++) {
        if (a[i] < b[i])
            return 1;
    }

    return 0;
}

/* return: 1 ge, 0 not ge */
static int Address2IPv6Ge(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    if (Address2IPv6Eq(a,b) == 1)
        return 1;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
    }

    return 0;
}

int Address2CmpIPv6(DetectAddress2Data *a, DetectAddress2Data *b) {
    u_int32_t net_a[4], net_b[4], brd_a[4], brd_b[4];

    brd_a[0] = net_a[0] = a->ip[0] & a->mask[0];
    brd_a[1] = net_a[1] = a->ip[1] & a->mask[1];
    brd_a[2] = net_a[2] = a->ip[2] & a->mask[2];
    brd_a[3] = net_a[3] = a->ip[3] & a->mask[3];

    brd_a[0] |=~ a->mask[0];
    brd_a[1] |=~ a->mask[1];
    brd_a[2] |=~ a->mask[2];
    brd_a[3] |=~ a->mask[3];

    brd_b[0] = net_b[0] = b->ip[0] & b->mask[0];
    brd_b[1] = net_b[1] = b->ip[1] & b->mask[1];
    brd_b[2] = net_b[2] = b->ip[2] & b->mask[2];
    brd_b[3] = net_b[3] = b->ip[3] & b->mask[3];

    brd_b[0] |=~ b->mask[0];
    brd_b[1] |=~ b->mask[1];
    brd_b[2] |=~ b->mask[2];
    brd_b[3] |=~ b->mask[3];

    /* ADDRESS_EQ */
    if (Address2IPv6Eq(a->ip, b->ip) == 1 &&
        Address2IPv6Eq(a->mask, b->mask) == 1) {
//        printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    } else if (Address2IPv6Eq(net_a, net_b) == 1 &&
               Address2IPv6Eq(brd_a, brd_b) == 1) {
//        printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    /* ADDRESS_ES */
    } else if (Address2IPv6Ge(net_a, net_b) == 1 &&
               Address2IPv6Lt(net_a, brd_b) == 1 &&
               Address2IPv6Le(brd_a, brd_b) == 1) {
//        printf("ADDRESS_ES\n");
        return ADDRESS_ES;
    /* ADDRESS_EB */
    } else if (Address2IPv6Le(net_a, net_b) == 1 &&
               Address2IPv6Ge(brd_a, brd_b) == 1) {
//        printf("ADDRESS_EB\n");
        return ADDRESS_EB;
    } else if (Address2IPv6Lt(net_a, net_b) == 1 &&
               Address2IPv6Le(brd_a, net_b) == 1) {
//        printf("ADDRESS_LT\n");
        return ADDRESS_LT;
    } else if (Address2IPv6Ge(net_a, brd_b) == 1) {
//        printf("ADDRESS_GT\n");
        return ADDRESS_GT;
    } else {
        /* should be unreachable */
//        printf("Internal Error: should be unreachable\n");
    }

//    printf ("ADDRESS_ER\n");
    return ADDRESS_ER;
}

int Address2Cmp(DetectAddress2Data *a, DetectAddress2Data *b) {
    if (a->family != b->family)
        return ADDRESS_ER;

    if (a->family == AF_INET)
        return Address2CmpIPv4(a,b);
    else if (a->family == AF_INET6)
        return Address2CmpIPv6(a,b);

    return ADDRESS_ER;
}

void DetectAddress2ParseIPv6CIDR(int cidr, struct in6_addr *in6) {
    int i = 0;

    //printf("CIDR: %d\n", cidr);

    memset(in6, 0, sizeof(struct in6_addr));

    while (cidr > 8) {
        in6->s6_addr[i] = 0xff;
        cidr -= 8;
        i++;
    }

    while (cidr > 0) {
        in6->s6_addr[i] |= 0x80;
        if (--cidr > 0)
             in6->s6_addr[i] = in6->s6_addr[i] >> 1;
    }
}

int Address2Parse(DetectAddress2Data *dd, char *str) {
    char *ip = strdup(str);
    char *mask = NULL;
    char *ip2 = NULL;
    char *ip6 = NULL;
    int r = 0;

    if ((ip6 = strchr(str,':')) == NULL) {
        /* IPv4 Address2 */
        struct in_addr in;

        dd->family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL)  {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;
            u_int32_t ip4addr = 0;
            u_int32_t netmask = 0;

            char *t = NULL;
            if ((t = strchr (mask,'.')) == NULL) {
                /* 1.2.3.4/24 format */

                int cidr = atoi(mask);
                netmask = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0) {
                    goto error;
                }
        
                netmask = in.s_addr;
                //printf("Address2Parse: dd->mask %X\n", dd->mask);
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
        
            ip4addr = in.s_addr;

            dd->ip[0] = dd->mask[0] = ip4addr & netmask;
            dd->mask[0] |=~ netmask;

            //printf("Address2Parse: dd->ip %X\n", dd->ip);
        } else if ((ip2 = strchr(ip, '-')) != NULL)  {
            /* 1.2.3.4-1.2.3.6 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
            dd->ip[0] = in.s_addr;

            r = inet_pton(AF_INET, ip2, &in);
            if (r <= 0) {
                goto error;
            }
            dd->mask[0] = in.s_addr;

            /* a>b is illegal, a=b is ok */
            if (ntohl(dd->ip[0]) > ntohl(dd->mask[0])) {
                goto error;
            }

        } else {
            /* 1.2.3.4 format */
            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
            /* single host */
            dd->ip[0] = in.s_addr;
            dd->mask[0] = in.s_addr;
            //printf("Address2Parse: dd->ip %X\n", dd->ip);
        }
    } else {
        /* IPv6 Address2 */
        struct in6_addr in6, mask6;

        dd->family = AF_INET6;

        if ((mask = strchr(ip, '/')) != NULL)  {
            ip[mask - ip] = '\0';
            mask++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }
            memcpy(&dd->ip, &in6.s6_addr, sizeof(dd->ip));

            DetectAddress2ParseIPv6CIDR(atoi(mask), &mask6);
            memcpy(&dd->mask, &mask6.s6_addr, sizeof(dd->mask));
/*
            int i;
            printf("ip6   0x");
            for (i = 0; i < 16; i++)
                printf("%02X", in6.s6_addr[i]);
            printf("\n");

            printf("mask6 0x");
            for (i = 0; i < 16; i++)
                printf("%02X", mask6.s6_addr[i]);
            printf("\n");
*/
        } else {
            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }

            memcpy(&dd->ip, &in6.s6_addr, sizeof(dd->ip));
            dd->mask[0] = 0xffffffff;
            dd->mask[1] = 0xffffffff;
            dd->mask[2] = 0xffffffff;
            dd->mask[3] = 0xffffffff;
        }

    }

    return 0;

error:
    if (ip) free(ip);
    return -1;
}

DetectAddress2Data *DetectAddress2Parse(char *str) {
    DetectAddress2Data *dd;

    dd = malloc(sizeof(DetectAddress2Data));
    if (dd == NULL) {
        printf("DetectAddress2Setup malloc failed\n");
        goto error;
    }

    if (Address2Parse(dd, str) < 0) {
        goto error;
    }

    return dd;

error:
    if (dd) free(dd);
    return NULL;
}

int DetectAddress2Setup (Signature *s, SigMatch *m, char *addressstr)
{
    char *str = addressstr;
    char dubbed = 0;

    /* strip "'s */
    if (addressstr[0] == '\"' && addressstr[strlen(addressstr)-1] == '\"') {
        str = strdup(addressstr+1);
        str[strlen(addressstr)-2] = '\0';
        dubbed = 1;
    }


    if (dubbed) free(str);
    return 0;
}

void DetectAddress2Free(DetectAddress2Data *dd) {
    free(dd);
}

int DetectAddress2Match (DetectAddress2Data *dd, Address *a) {
    if (dd->family != a->family)
        return 0;

    switch (a->family) {
        case AF_INET:
            //printf("a->addr_data32[0] %u dd->ip[0] %u, dd->mask[0] %u", a->addr_data32[0], dd->ip[0], dd->mask[0]);
            if (a->addr_data32[0] >= dd->ip[0] && a->addr_data32[0] <= dd->mask[0]) {
                return 1;
            } else {
                return 0;
            }
            break;
        case AF_INET6:
            //printf("\n0x%08X 0x%08X\n", dd->ip[0] & dd->mask[0], a->addr_data32[0] & dd->mask[0]);
            //printf("0x%08X 0x%08X\n", dd->ip[1] & dd->mask[1], a->addr_data32[1] & dd->mask[1]);
            //printf("0x%08X 0x%08X\n", dd->ip[2] & dd->mask[2], a->addr_data32[2] & dd->mask[2]);
            //printf("0x%08X 0x%08X\n", dd->ip[3] & dd->mask[3], a->addr_data32[3] & dd->mask[3]);

            if ((dd->ip[0] & dd->mask[0]) == (a->addr_data32[0] & dd->mask[0]) &&
                (dd->ip[1] & dd->mask[1]) == (a->addr_data32[1] & dd->mask[1]) &&
                (dd->ip[2] & dd->mask[2]) == (a->addr_data32[2] & dd->mask[2]) &&
                (dd->ip[3] & dd->mask[3]) == (a->addr_data32[3] & dd->mask[3]))
            {
                return 1;
            } else {
                return 0;
            }
            break;
    }

    return 0;
}

void DetectAddress2DataPrint(DetectAddress2Data *ad) {
    if (ad == NULL)
        return;

    if (ad->family == AF_INET) {
        struct in_addr in;
        char s[16];

        memcpy(&in, &ad->ip[0], sizeof(in));
        inet_ntop(AF_INET, &in, s, sizeof(s));
        printf("%s/", s);
        memcpy(&in, &ad->mask[0], sizeof(in));
        inet_ntop(AF_INET, &in, s, sizeof(s));
        printf("%s\n", s);
    } else if (ad->family == AF_INET6) {

    }
}


/* TESTS */

int Address2TestParse01 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("1.2.3.4");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse02 (void) {
    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4");
    if (dd) {
        if (dd->mask[0] != 0x04030201 ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse03 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("1.2.3.4/255.255.255.0");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse04 (void) {
    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/255.255.255.0");
    if (dd) {
        if (dd->mask[0] != 0xff030201 ||
            dd->ip[0]   != 0x00030201) {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse05 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("1.2.3.4/24");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse06 (void) {
    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/24");
    if (dd) {
        if (dd->mask[0] != 0xff030201 ||
            dd->ip[0]   != 0x00030201) {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse07 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/3");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse08 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/3");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0x000000E0 || dd->mask[1] != 0x00000000 ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse09 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::1/128");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse10 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/128");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0xFFFFFFFF || dd->mask[1] != 0xFFFFFFFF ||
            dd->mask[2] != 0xFFFFFFFF || dd->mask[3] != 0xFFFFFFFF)
        {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse11 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/48");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse12 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/48");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0xFFFFFFFF || dd->mask[1] != 0x0000FFFF ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}
int Address2TestParse13 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/16");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse14 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/16");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0x0000FFFF || dd->mask[1] != 0x00000000 ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse15 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/0");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse16 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("2001::/0");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0x00000000 || dd->mask[1] != 0x00000000 ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse17 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("1.2.3.4-1.2.3.6");
    if (dd) {
        DetectAddress2Free(dd);
        return 1;
    }

    return 0;
}

int Address2TestParse18 (void) {
    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4-1.2.3.6");
    if (dd) {
        if (dd->mask[0] != 0x06030201 ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestParse19 (void) {
    DetectAddress2Data *dd = NULL;
    dd = DetectAddress2Parse("1.2.3.6-1.2.3.4");
    if (dd) {
        DetectAddress2Free(dd);
        return 0;
    }

    return 1;
}

int Address2TestMatch01 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.4", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/24");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 0)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch02 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.127", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/25");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 0)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch03 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.128", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/25");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 1)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch04 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.2.255", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/25");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 1)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch05 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.4", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("1.2.3.4/32");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 0)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch06 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.4", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("0.0.0.0/0.0.0.0");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 0)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch07 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::1", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("2001::/3");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 0)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch08 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "1999:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("2001::/3");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 1)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch09 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::2", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("2001::1/128");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 1)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch10 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::2", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("2001::1/126");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 0)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestMatch11 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::3", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddress2Data *dd = NULL;
    int result = 1;

    dd = DetectAddress2Parse("2001::1/127");
    if (dd) {
        if (DetectAddress2Match(dd,&a) == 1)
            result = 0;

        DetectAddress2Free(dd);
        return result;
    }

    return 0;
}

int Address2TestCmp01 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp02 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.0.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_EB)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp03 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_ES)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp04 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_LT)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp05 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_GT)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp06 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.1.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmpIPv407 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.1.128-192.168.2.128");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_LE)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmpIPv408 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("192.168.1.128-192.168.2.128");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_GE)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp07 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("2001::1/3");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp08 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("2001::/8");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_EB)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp09 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("2001::/8");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("2001::/3");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_ES)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp10 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("2001:1:2:3:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("2001:1:2:4:0:0:0:0/64");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_LT)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp11 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("2001:1:2:4:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("2001:1:2:3:0:0:0:0/64");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_GT)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestCmp12 (void) {
    DetectAddress2Data *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddress2Parse("2001:1:2:3:1:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddress2Parse("2001:1:2:3:2:0:0:0/64");
    if (db == NULL) goto error;

    if (Address2Cmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddress2Free(da);
    DetectAddress2Free(db);
    return result;

error:
    if (da) DetectAddress2Free(da);
    if (db) DetectAddress2Free(db);
    return 0;
}

int Address2TestIPv6Gt01 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (Address2IPv6Gt(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Gt02 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Gt(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Gt03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Gt(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Gt04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 5 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Gt(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Lt01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Lt(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Lt02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (Address2IPv6Lt(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Lt03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Lt(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Lt04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (Address2IPv6Lt(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Eq01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Eq02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (Address2IPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Eq03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Eq(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Eq04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (Address2IPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Le01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Le02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (Address2IPv6Le(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Le03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Le04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (Address2IPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Ge01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestIPv6Ge02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (Address2IPv6Ge(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Ge03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (Address2IPv6Ge(a,b) == 1)
        result = 1;

    return result;
}

int Address2TestIPv6Ge04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (Address2IPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

int Address2TestAddress2GroupSetup01 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("1.2.3.4");
    if (r == 0) {
        result = 1;
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup02 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("1.2.3.4");
    if (r == 0 && head != NULL) {
        result = 1;
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup03 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("1.2.3.4");
    if (r == 0 && head != NULL) {
        DetectAddress2Group *prev_head = head;

        r = DetectAddress2GroupSetup("1.2.3.3");
        if (r == 0 && head != prev_head && head != NULL && head->next == prev_head) {
            result = 1;
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup04 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("1.2.3.4");
    if (r == 0 && head != NULL) {
        DetectAddress2Group *prev_head = head;

        r = DetectAddress2GroupSetup("1.2.3.3");
        if (r == 0 && head != prev_head && head != NULL && head->next == prev_head) {
            prev_head = head;

            r = DetectAddress2GroupSetup("1.2.3.2");
            if (r == 0 && head != prev_head && head != NULL && head->next == prev_head) {
                result = 1;
            }
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup05 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("1.2.3.2");
    if (r == 0 && head != NULL) {
        DetectAddress2Group *prev_head = head;

        r = DetectAddress2GroupSetup("1.2.3.3");
        if (r == 0 && head == prev_head && head != NULL && head->next != prev_head) {
            prev_head = head;

            r = DetectAddress2GroupSetup("1.2.3.4");
            if (r == 0 && head == prev_head && head != NULL && head->next != prev_head) {
                result = 1;
            }
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup06 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("1.2.3.2");
    if (r == 0 && head != NULL) {
        DetectAddress2Group *prev_head = head;

        r = DetectAddress2GroupSetup("1.2.3.2");
        if (r == 0 && head == prev_head && head != NULL && head->next == NULL) {
            result = 1;
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup07 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("10.0.0.0/8");
    if (r == 0 && head != NULL) {
        r = DetectAddress2GroupSetup("10.10.10.10");
        if (r == 0 && head != NULL && head->next != NULL && head->next->next != NULL) {
            result = 1;
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup08 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("10.10.10.10");
    if (r == 0 && head != NULL) {
        r = DetectAddress2GroupSetup("10.0.0.0/8");
        if (r == 0 && head != NULL && head->next != NULL && head->next->next != NULL) {
            result = 1;
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup09 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("10.10.10.0/24");
    if (r == 0 && head != NULL) {
        r = DetectAddress2GroupSetup("10.10.10.10-10.10.11.1");
        if (r == 0 && head != NULL && head->next != NULL && head->next->next != NULL) {
            result = 1;
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup10 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("10.10.10.10-10.10.11.1");
    if (r == 0 && head != NULL) {
        r = DetectAddress2GroupSetup("10.10.10.0/24");
        if (r == 0 && head != NULL && head->next != NULL && head->next->next != NULL) {
            result = 1;
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup11 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("10.10.10.10-10.10.11.1");
    if (r == 0) {
        r = DetectAddress2GroupSetup("10.10.10.0/24");
        if (r == 0) {
            r = DetectAddress2GroupSetup("0.0.0.0/0");
            if (r == 0) {
                DetectAddress2Group *one = head, *two = one->next,
                                    *three = two->next, *four = three->next,
                                    *five = four->next;

                /* result should be:
                 * 0.0.0.0/10.10.9.255
                 * 10.10.10.0/10.10.10.9
                 * 10.10.10.10/10.10.10.255
                 * 10.10.11.0/10.10.11.1
                 * 10.10.11.2/255.255.255.255
                 */
                if (one->ad->ip[0]   == 0x00000000 && one->ad->mask[0]   == 0xFF090A0A &&
                    two->ad->ip[0]   == 0x000A0A0A && two->ad->mask[0]   == 0x090A0A0A &&
                    three->ad->ip[0] == 0x0A0A0A0A && three->ad->mask[0] == 0xFF0A0A0A &&
                    four->ad->ip[0]  == 0x000B0A0A && four->ad->mask[0]  == 0x010B0A0A &&
                    five->ad->ip[0]  == 0x020B0A0A && five->ad->mask[0]  == 0xFFFFFFFF) {
                    result = 1;
                }
            }
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup12 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("10.10.10.10-10.10.11.1");
    if (r == 0) {
        r = DetectAddress2GroupSetup("0.0.0.0/0");
        if (r == 0) {
            r = DetectAddress2GroupSetup("10.10.10.0/24");
            if (r == 0) {
                DetectAddress2Group *one = head, *two = one->next,
                                    *three = two->next, *four = three->next,
                                    *five = four->next;

                /* result should be:
                 * 0.0.0.0/10.10.9.255
                 * 10.10.10.0/10.10.10.9
                 * 10.10.10.10/10.10.10.255
                 * 10.10.11.0/10.10.11.1
                 * 10.10.11.2/255.255.255.255
                 */
                if (one->ad->ip[0]   == 0x00000000 && one->ad->mask[0]   == 0xFF090A0A &&
                    two->ad->ip[0]   == 0x000A0A0A && two->ad->mask[0]   == 0x090A0A0A &&
                    three->ad->ip[0] == 0x0A0A0A0A && three->ad->mask[0] == 0xFF0A0A0A &&
                    four->ad->ip[0]  == 0x000B0A0A && four->ad->mask[0]  == 0x010B0A0A &&
                    five->ad->ip[0]  == 0x020B0A0A && five->ad->mask[0]  == 0xFFFFFFFF) {
                    result = 1;
                }
            }
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestAddress2GroupSetup13 (void) {
    int result = 0;
    int r = DetectAddress2GroupSetup("0.0.0.0/0");
    if (r == 0) {
        r = DetectAddress2GroupSetup("10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddress2GroupSetup("10.10.10.0/24");
            if (r == 0) {
                DetectAddress2Group *one = head, *two = one->next,
                                    *three = two->next, *four = three->next,
                                    *five = four->next;

                /* result should be:
                 * 0.0.0.0/10.10.9.255
                 * 10.10.10.0/10.10.10.9
                 * 10.10.10.10/10.10.10.255
                 * 10.10.11.0/10.10.11.1
                 * 10.10.11.2/255.255.255.255
                 */
                if (one->ad->ip[0]   == 0x00000000 && one->ad->mask[0]   == 0xFF090A0A &&
                    two->ad->ip[0]   == 0x000A0A0A && two->ad->mask[0]   == 0x090A0A0A &&
                    three->ad->ip[0] == 0x0A0A0A0A && three->ad->mask[0] == 0xFF0A0A0A &&
                    four->ad->ip[0]  == 0x000B0A0A && four->ad->mask[0]  == 0x010B0A0A &&
                    five->ad->ip[0]  == 0x020B0A0A && five->ad->mask[0]  == 0xFFFFFFFF) {
                    result = 1;
                }
            }
        }
    }

    DetectAddress2GroupCleanupList();
    return result;
}

int Address2TestCutIPv401(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c = NULL;
    a = DetectAddress2Parse("1.2.3.0/255.255.255.0");
    b = DetectAddress2Parse("1.2.2.0-1.2.3.4");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv402(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.0/255.255.255.0");
    b = DetectAddress2Parse("1.2.2.0-1.2.3.4");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv403(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.0/255.255.255.0");
    b = DetectAddress2Parse("1.2.2.0-1.2.3.4");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00020201 && a->mask[0] != 0xff020201) {
        goto error;
    }
    if (b->ip[0] != 0x00030201 && b->mask[0] != 0x04030201) {
        goto error;
    }
    if (c->ip[0] != 0x05030201 && c->mask[0] != 0xff030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv404(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.3-1.2.3.6");
    b = DetectAddress2Parse("1.2.3.0-1.2.3.5");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->mask[0] != 0x04030201) {
        goto error;
    }
    if (c->ip[0] != 0x05030201 && c->mask[0] != 0x06030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv405(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.3-1.2.3.6");
    b = DetectAddress2Parse("1.2.3.0-1.2.3.9");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->mask[0] != 0x06030201) {
        goto error;
    }
    if (c->ip[0] != 0x07030201 && c->mask[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv406(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.0-1.2.3.9");
    b = DetectAddress2Parse("1.2.3.3-1.2.3.6");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->mask[0] != 0x06030201) {
        goto error;
    }
    if (c->ip[0] != 0x07030201 && c->mask[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv407(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.0-1.2.3.6");
    b = DetectAddress2Parse("1.2.3.0-1.2.3.9");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x06030201) {
        goto error;
    }
    if (b->ip[0] != 0x07030201 && b->mask[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv408(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.3-1.2.3.9");
    b = DetectAddress2Parse("1.2.3.0-1.2.3.9");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x02030201) {
        DetectAddress2DataPrint(a);
        DetectAddress2DataPrint(b);
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->mask[0] != 0x09030201) {
        DetectAddress2DataPrint(a);
        DetectAddress2DataPrint(b);
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv409(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.0-1.2.3.9");
    b = DetectAddress2Parse("1.2.3.0-1.2.3.6");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x06030201) {
        goto error;
    }
    if (b->ip[0] != 0x07030201 && b->mask[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int Address2TestCutIPv410(void) {
    DetectAddress2Data *a;
    DetectAddress2Data *b;
    DetectAddress2Data *c;
    a = DetectAddress2Parse("1.2.3.0-1.2.3.9");
    b = DetectAddress2Parse("1.2.3.3-1.2.3.9");

    if (Address2CutIPv4(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->mask[0] != 0x02030201) {
        DetectAddress2DataPrint(a);
        DetectAddress2DataPrint(b);
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->mask[0] != 0x09030201) {
        DetectAddress2DataPrint(a);
        DetectAddress2DataPrint(b);
        goto error;
    }

    return 1;
error:
    return 0;
}

void DetectAddress2Tests(void) {
    UtRegisterTest("Address2TestParse01", Address2TestParse01, 1);
    UtRegisterTest("Address2TestParse02", Address2TestParse02, 1);
    UtRegisterTest("Address2TestParse03", Address2TestParse03, 1);
    UtRegisterTest("Address2TestParse04", Address2TestParse04, 1);
    UtRegisterTest("Address2TestParse05", Address2TestParse05, 1);
    UtRegisterTest("Address2TestParse06", Address2TestParse06, 1);
    UtRegisterTest("Address2TestParse07", Address2TestParse07, 1);
    UtRegisterTest("Address2TestParse08", Address2TestParse08, 1);
    UtRegisterTest("Address2TestParse09", Address2TestParse09, 1);
    UtRegisterTest("Address2TestParse10", Address2TestParse10, 1);
    UtRegisterTest("Address2TestParse11", Address2TestParse11, 1);
    UtRegisterTest("Address2TestParse12", Address2TestParse12, 1);
    UtRegisterTest("Address2TestParse13", Address2TestParse13, 1);
    UtRegisterTest("Address2TestParse14", Address2TestParse14, 1);
    UtRegisterTest("Address2TestParse15", Address2TestParse15, 1);
    UtRegisterTest("Address2TestParse16", Address2TestParse16, 1);
    UtRegisterTest("Address2TestParse17", Address2TestParse17, 1);
    UtRegisterTest("Address2TestParse18", Address2TestParse18, 1);
    UtRegisterTest("Address2TestParse19", Address2TestParse19, 1);

    UtRegisterTest("Address2TestMatch01", Address2TestMatch01, 1);
    UtRegisterTest("Address2TestMatch02", Address2TestMatch02, 1);
    UtRegisterTest("Address2TestMatch03", Address2TestMatch03, 1);
    UtRegisterTest("Address2TestMatch04", Address2TestMatch04, 1);
    UtRegisterTest("Address2TestMatch05", Address2TestMatch05, 1);
    UtRegisterTest("Address2TestMatch06", Address2TestMatch06, 1);
    UtRegisterTest("Address2TestMatch07", Address2TestMatch07, 1);
    UtRegisterTest("Address2TestMatch08", Address2TestMatch08, 1);
    UtRegisterTest("Address2TestMatch09", Address2TestMatch09, 1);
    UtRegisterTest("Address2TestMatch10", Address2TestMatch10, 1);
    UtRegisterTest("Address2TestMatch11", Address2TestMatch11, 1);

    UtRegisterTest("Address2TestCmp01",   Address2TestCmp01, 1);
    UtRegisterTest("Address2TestCmp02",   Address2TestCmp02, 1);
    UtRegisterTest("Address2TestCmp03",   Address2TestCmp03, 1);
    UtRegisterTest("Address2TestCmp04",   Address2TestCmp04, 1);
    UtRegisterTest("Address2TestCmp05",   Address2TestCmp05, 1);
    UtRegisterTest("Address2TestCmp06",   Address2TestCmp06, 1);
    UtRegisterTest("Address2TestCmpIPv407", Address2TestCmpIPv407, 1);
    UtRegisterTest("Address2TestCmpIPv408", Address2TestCmpIPv408, 1);

    UtRegisterTest("Address2TestCmp07",   Address2TestCmp07, 1);
    UtRegisterTest("Address2TestCmp08",   Address2TestCmp08, 1);
    UtRegisterTest("Address2TestCmp09",   Address2TestCmp09, 1);
    UtRegisterTest("Address2TestCmp10",   Address2TestCmp10, 1);
    UtRegisterTest("Address2TestCmp11",   Address2TestCmp11, 1);
    UtRegisterTest("Address2TestCmp12",   Address2TestCmp12, 1);

    UtRegisterTest("Address2TestIPv6Gt01",   Address2TestIPv6Gt01, 1);
    UtRegisterTest("Address2TestIPv6Gt02",   Address2TestIPv6Gt02, 1);
    UtRegisterTest("Address2TestIPv6Gt03",   Address2TestIPv6Gt03, 1);
    UtRegisterTest("Address2TestIPv6Gt04",   Address2TestIPv6Gt04, 1);

    UtRegisterTest("Address2TestIPv6Lt01",   Address2TestIPv6Lt01, 1);
    UtRegisterTest("Address2TestIPv6Lt02",   Address2TestIPv6Lt02, 1);
    UtRegisterTest("Address2TestIPv6Lt03",   Address2TestIPv6Lt03, 1);
    UtRegisterTest("Address2TestIPv6Lt04",   Address2TestIPv6Lt04, 1);

    UtRegisterTest("Address2TestIPv6Eq01",   Address2TestIPv6Eq01, 1);
    UtRegisterTest("Address2TestIPv6Eq02",   Address2TestIPv6Eq02, 1);
    UtRegisterTest("Address2TestIPv6Eq03",   Address2TestIPv6Eq03, 1);
    UtRegisterTest("Address2TestIPv6Eq04",   Address2TestIPv6Eq04, 1);

    UtRegisterTest("Address2TestIPv6Le01",   Address2TestIPv6Le01, 1);
    UtRegisterTest("Address2TestIPv6Le02",   Address2TestIPv6Le02, 1);
    UtRegisterTest("Address2TestIPv6Le03",   Address2TestIPv6Le03, 1);
    UtRegisterTest("Address2TestIPv6Le04",   Address2TestIPv6Le04, 1);

    UtRegisterTest("Address2TestIPv6Ge01",   Address2TestIPv6Ge01, 1);
    UtRegisterTest("Address2TestIPv6Ge02",   Address2TestIPv6Ge02, 1);
    UtRegisterTest("Address2TestIPv6Ge03",   Address2TestIPv6Ge03, 1);
    UtRegisterTest("Address2TestIPv6Ge04",   Address2TestIPv6Ge04, 1);

    UtRegisterTest("Address2TestAddress2GroupSetup01", Address2TestAddress2GroupSetup01, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup02", Address2TestAddress2GroupSetup02, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup03", Address2TestAddress2GroupSetup03, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup04", Address2TestAddress2GroupSetup04, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup05", Address2TestAddress2GroupSetup05, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup06", Address2TestAddress2GroupSetup06, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup07", Address2TestAddress2GroupSetup07, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup08", Address2TestAddress2GroupSetup08, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup09", Address2TestAddress2GroupSetup09, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup10", Address2TestAddress2GroupSetup10, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup11", Address2TestAddress2GroupSetup11, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup12", Address2TestAddress2GroupSetup12, 1);
    UtRegisterTest("Address2TestAddress2GroupSetup13", Address2TestAddress2GroupSetup13, 1);
/*
    UtRegisterTest("Address2TestCutIPv401", Address2TestCutIPv401, 1);
    UtRegisterTest("Address2TestCutIPv402", Address2TestCutIPv402, 1);
    UtRegisterTest("Address2TestCutIPv403", Address2TestCutIPv403, 1);
    UtRegisterTest("Address2TestCutIPv404", Address2TestCutIPv404, 1);
    UtRegisterTest("Address2TestCutIPv405", Address2TestCutIPv405, 1);
    UtRegisterTest("Address2TestCutIPv406", Address2TestCutIPv406, 1);
    UtRegisterTest("Address2TestCutIPv407", Address2TestCutIPv407, 1);
    UtRegisterTest("Address2TestCutIPv408", Address2TestCutIPv408, 1);
    UtRegisterTest("Address2TestCutIPv409", Address2TestCutIPv409, 1);
    UtRegisterTest("Address2TestCutIPv410", Address2TestCutIPv410, 1);
*/
}


