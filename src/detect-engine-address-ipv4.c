/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-engine-address.h"
#include "detect-engine-siggroup.h"

int DetectAddressCmpIPv4(DetectAddressData *a, DetectAddressData *b) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->ip2[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->ip2[0]);

    /* ADDRESS_EQ */
    if (a_ip1 == b_ip1 && a_ip2 == b_ip2) {
        //printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    /* ADDRESS_ES */
    } else if (a_ip1 >= b_ip1 && a_ip1 <= b_ip2 && a_ip2 <= b_ip2) {
        //printf("ADDRESS_ES\n");
        return ADDRESS_ES;
    /* ADDRESS_EB */
    } else if (a_ip1 <= b_ip1 && a_ip2 >= b_ip2) {
        //printf("ADDRESS_EB\n");
        return ADDRESS_EB;
    } else if (a_ip1 < b_ip1 && a_ip2 < b_ip2 && a_ip2 >= b_ip1) {
        //printf("ADDRESS_LE\n");
        return ADDRESS_LE;
    } else if (a_ip1 < b_ip1 && a_ip2 < b_ip2) {
        //printf("ADDRESS_LT\n");
        return ADDRESS_LT;
    } else if (a_ip1 > b_ip1 && a_ip1 <= b_ip2 && a_ip2 > b_ip2) {
        //printf("ADDRESS_GE\n");
        return ADDRESS_GE;
    } else if (a_ip1 > b_ip2) {
        //printf("ADDRESS_GT\n");
        return ADDRESS_GT;
    } else {
        /* should be unreachable */
        //printf("Internal Error: should be unreachable\n");
    }

    return ADDRESS_ER;
}

//#define DBG
/* Cut groups and merge sigs
 *
 * a = 1.2.3.4, b = 1.2.3.4-1.2.3.5
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
int DetectAddressGroupCutIPv4(DetectAddressGroup *a, DetectAddressGroup *b, DetectAddressGroup **c) {
    u_int32_t a_ip1 = ntohl(a->ad->ip[0]);
    u_int32_t a_ip2 = ntohl(a->ad->ip2[0]);
    u_int32_t b_ip1 = ntohl(b->ad->ip[0]);
    u_int32_t b_ip2 = ntohl(b->ad->ip2[0]);
    DetectPort *port = NULL;

    /* default to NULL */
    *c = NULL;

    int r = DetectAddressCmpIPv4(a->ad,b->ad);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        printf("we shouldn't be here\n");
        goto error;
    }

    /* get a place to temporary put sigs lists */
    DetectAddressGroup *tmp = DetectAddressGroupInit();
    if (tmp == NULL) {
        goto error;
    }
    memset(tmp,0,sizeof(DetectAddressGroup));

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    if (r == ADDRESS_LE) {
#ifdef DBG
        printf("DetectAddressGroupCutIPv4: r == ADDRESS_LE\n");
#endif
        a->ad->ip[0]  = htonl(a_ip1);
        a->ad->ip2[0] = htonl(b_ip1 - 1);

        b->ad->ip[0]  = htonl(b_ip1);
        b->ad->ip2[0] = htonl(a_ip2);

        DetectAddressGroup *tmp_c;
        tmp_c = DetectAddressGroupInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->ad = DetectAddressDataInit();
        if (tmp_c->ad == NULL) {
            goto error;
        }

        tmp_c->ad->family  = AF_INET;
        tmp_c->ad->ip[0]   = htonl(a_ip2 + 1);
        tmp_c->ad->ip2[0]  = htonl(b_ip2);
        *c = tmp_c;

        SigGroupHeadCopySigs(b->sh,&tmp_c->sh);
        SigGroupHeadCopySigs(a->sh,&b->sh);

        for (port = b->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(&tmp_c->port, port);
        }
        for (port = a->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(&b->port, port);
        }

        tmp_c->cnt += b->cnt;
        b->cnt += a->cnt;

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_GE) {
#ifdef DBG
        printf("DetectAddressGroupCutIPv4: r == ADDRESS_GE\n");
#endif
        a->ad->ip[0]   = htonl(b_ip1);
        a->ad->ip2[0] = htonl(a_ip1 - 1);

        b->ad->ip[0]   = htonl(a_ip1);
        b->ad->ip2[0] = htonl(b_ip2);

        DetectAddressGroup *tmp_c;
        tmp_c = DetectAddressGroupInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->ad = DetectAddressDataInit();
        if (tmp_c->ad == NULL) {
            goto error;
        }

        tmp_c->ad->family = AF_INET;
        tmp_c->ad->ip[0]  = htonl(b_ip2 + 1);
        tmp_c->ad->ip2[0] = htonl(a_ip2);
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

        for (port = a->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(&tmp->port, port);
        }
        for (port = b->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(&a->port, port);
        }
        for (port = tmp->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(&b->port, port);
        }
        for (port = tmp->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(&tmp_c->port, port);
        }

        tmp->cnt += a->cnt;
        a->cnt = 0;
        tmp_c->cnt += tmp->cnt;
        a->cnt += b->cnt;
        b->cnt += tmp->cnt;
        tmp->cnt = 0;

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
     * becomes[aaa[bbb]ccc]
     *
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    } else if (r == ADDRESS_ES) {
#ifdef DBG
        printf("DetectAddressGroupCutIPv4: r == ADDRESS_ES\n");
#endif
        if (a_ip1 == b_ip1) {
#ifdef DBG
            printf("DetectAddressGroupCutIPv4: 1\n");
#endif
            a->ad->ip[0]   = htonl(a_ip1);
            a->ad->ip2[0] = htonl(a_ip2);

            b->ad->ip[0]   = htonl(a_ip2 + 1);
            b->ad->ip2[0] = htonl(b_ip2);

            /* 'b' overlaps 'a' so 'a' needs the 'b' sigs */
            SigGroupHeadCopySigs(b->sh,&a->sh);

            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&a->port, port);
            }
            a->cnt += b->cnt;

        } else if (a_ip2 == b_ip2) {
#ifdef DBG
            printf("DetectAddressGroupCutIPv4: 2\n");
#endif
            a->ad->ip[0]   = htonl(b_ip1);
            a->ad->ip2[0] = htonl(a_ip1 - 1);

            b->ad->ip[0]   = htonl(a_ip1);
            b->ad->ip2[0] = htonl(a_ip2);

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupHeadCopySigs(a->sh,&b->sh);

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&b->port, port);
            }
            b->cnt += a->cnt;
        } else {
#ifdef DBG
            printf("3\n");
#endif
            a->ad->ip[0]   = htonl(b_ip1);
            a->ad->ip2[0] = htonl(a_ip1 - 1);

            b->ad->ip[0]   = htonl(a_ip1);
            b->ad->ip2[0] = htonl(a_ip2);

            DetectAddressGroup *tmp_c;
            tmp_c = DetectAddressGroupInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->ad = DetectAddressDataInit();
            if (tmp_c->ad == NULL) {
                goto error;
            }

            tmp_c->ad->family  = AF_INET;
            tmp_c->ad->ip[0]   = htonl(a_ip2 + 1);
            tmp_c->ad->ip2[0] = htonl(b_ip2);
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

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&tmp->port, port);
            }
            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&tmp_c->port, port);
            }
            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&a->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&b->port, port);
            }
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
     * part a: b_ip1 <-> b_ip2
     * part b: b_ip2 + 1 <-> a_ip2
     *
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> b_ip2
     *
     * 3 part [aaa[bbb]aaa]
     * becomes[aaa[bbb]ccc]
     *
     * part a: a_ip1 <-> b_ip2 - 1
     * part b: b_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_EB) {
#ifdef DBG
        printf("DetectAddressGroupCutIPv4: r == ADDRESS_EB\n");
#endif
        if (a_ip1 == b_ip1) {
#ifdef DBG
            printf("DetectAddressGroupCutIPv4: 1\n");
#endif
            a->ad->ip[0]   = htonl(b_ip1);
            a->ad->ip2[0] = htonl(b_ip2);

            b->ad->ip[0]   = htonl(b_ip2 + 1);
            b->ad->ip2[0] = htonl(a_ip2);

            /* 'b' overlaps 'a' so a needs the 'b' sigs */
            SigGroupHeadCopySigs(b->sh,&tmp->sh);
            SigGroupHeadClearSigs(b->sh);
            SigGroupHeadCopySigs(a->sh,&b->sh);
            SigGroupHeadCopySigs(tmp->sh,&a->sh);
            SigGroupHeadClearSigs(tmp->sh);

            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&tmp->port, b->port);
            }
            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&b->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&a->port, port);
            }
            tmp->cnt += b->cnt;
            b->cnt = 0;
            b->cnt += a->cnt;
            a->cnt += tmp->cnt;
            tmp->cnt = 0;
        } else if (a_ip2 == b_ip2) {
#ifdef DBG
            printf("DetectAddressGroupCutIPv4: 2\n");
#endif
            a->ad->ip[0]   = htonl(a_ip1);
            a->ad->ip2[0] = htonl(b_ip1 - 1);

            b->ad->ip[0]   = htonl(b_ip1);
            b->ad->ip2[0] = htonl(b_ip2);

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupHeadCopySigs(a->sh,&b->sh);

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&b->port, port);
            }

            b->cnt += a->cnt;
        } else {
#ifdef DBG
            printf("DetectAddressGroupCutIPv4: 3\n");
#endif
            a->ad->ip[0]   = htonl(a_ip1);
            a->ad->ip2[0] = htonl(b_ip1 - 1);

            b->ad->ip[0]   = htonl(b_ip1);
            b->ad->ip2[0] = htonl(b_ip2);

            DetectAddressGroup *tmp_c;
            tmp_c = DetectAddressGroupInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->ad = DetectAddressDataInit();
            if (tmp_c->ad == NULL) {
                goto error;
            }

            tmp_c->ad->family  = AF_INET;
            tmp_c->ad->ip[0]   = htonl(b_ip2 + 1);
            tmp_c->ad->ip2[0] = htonl(a_ip2);
            *c = tmp_c;

            /* 'a' stays the same wrt sigs
             * 'b' keeps it's own sigs and gets a's sigs prepended
             * 'c' gets 'a' sigs */
            SigGroupHeadCopySigs(a->sh,&b->sh);
            SigGroupHeadCopySigs(a->sh,&tmp_c->sh);

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&b->port, port);
            }
            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(&tmp_c->port, port);
            }

            b->cnt += a->cnt;
            tmp_c->cnt += a->cnt;
        }
    }

    DetectAddressGroupFree(tmp);
    return 0;

error:
    DetectAddressGroupFree(tmp);
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
int DetectAddressCutIPv4(DetectAddressData *a, DetectAddressData *b, DetectAddressData **c) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->ip2[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->ip2[0]);

    /* default to NULL */
    *c = NULL;

    int r = DetectAddressCmpIPv4(a,b);
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
        a->ip2[0] = htonl(b_ip1 - 1);

        b->ip[0]   = htonl(b_ip1);
        b->ip2[0] = htonl(a_ip2);

        DetectAddressData *tmp_c;
        tmp_c = DetectAddressDataInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET;
        tmp_c->ip[0]   = htonl(a_ip2 + 1);
        tmp_c->ip2[0] = htonl(b_ip2);
        *c = tmp_c;

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */ 
    } else if (r == ADDRESS_GE) {
        a->ip[0]   = htonl(b_ip1);
        a->ip2[0] = htonl(a_ip1 - 1);

        b->ip[0]   = htonl(a_ip1);
        b->ip2[0] = htonl(b_ip2);

        DetectAddressData *tmp_c;
        tmp_c = DetectAddressDataInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET;
        tmp_c->ip[0]   = htonl(b_ip2 + 1);
        tmp_c->ip2[0] = htonl(a_ip2);
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
            a->ip2[0] = htonl(a_ip2);

            b->ip[0]   = htonl(a_ip2 + 1);
            b->ip2[0] = htonl(b_ip2);
        } else if (a_ip2 == b_ip2) {
            a->ip[0]   = htonl(b_ip1);
            a->ip2[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->ip2[0] = htonl(a_ip2);
        } else {
            a->ip[0]   = htonl(b_ip1);
            a->ip2[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->ip2[0] = htonl(a_ip2);

            DetectAddressData *tmp_c;
            tmp_c = DetectAddressDataInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET;
            tmp_c->ip[0]   = htonl(a_ip2 + 1);
            tmp_c->ip2[0] = htonl(b_ip2);
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
            a->ip2[0] = htonl(b_ip2);

            b->ip[0]   = htonl(b_ip2 + 1);
            b->ip2[0] = htonl(a_ip2);
        } else if (a_ip2 == b_ip2) {
            a->ip[0]   = htonl(a_ip1);
            a->ip2[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->ip2[0] = htonl(b_ip2);
        } else {
            a->ip[0]   = htonl(a_ip1);
            a->ip2[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->ip2[0] = htonl(b_ip2);

            DetectAddressData *tmp_c;
            tmp_c = DetectAddressDataInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET;
            tmp_c->ip[0]   = htonl(b_ip2 + 1);
            tmp_c->ip2[0] = htonl(a_ip2);
            *c = tmp_c;
        }
    }

    return 0;

error:
    return -1;
}


/* a = 1.2.3.4
 * must result in: a == 0.0.0.0-1.2.3.3, b == 1.2.3.5-255.255.255.255
 *
 * a = 0.0.0.0/32
 * must result in: a == 0.0.0.1-255.255.255.255, b == NULL
 *
 * a = 255.255.255.255
 * must result in: a == 0.0.0.0-255.255.255.254, b == NULL
 *
 */
int DetectAddressCutNotIPv4(DetectAddressData *a, DetectAddressData **b) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->ip2[0]);

    /* default to NULL */
    *b = NULL;

    if (a_ip1 != 0x00000000 && a_ip2 != 0xFFFFFFFF) {
        a->ip[0]  = htonl(0x00000000);
        a->ip2[0] = htonl(a_ip1 - 1);

        DetectAddressData *tmp_b;
        tmp_b = DetectAddressDataInit();
        if (tmp_b == NULL) {
            goto error;
        }
        tmp_b->family = AF_INET;
        tmp_b->ip[0]  = htonl(a_ip2 + 1);
        tmp_b->ip2[0] = htonl(0xFFFFFFFF);
        *b = tmp_b;

    } else if (a_ip1 == 0x00000000 && a_ip2 != 0xFFFFFFFF) {
        a->ip[0]   = htonl(a_ip2 + 1);
        a->ip2[0] = htonl(0xFFFFFFFF);

    } else if (a_ip1 != 0x00000000 && a_ip2 == 0xFFFFFFFF) {
        a->ip[0]   = htonl(0x00000000);
        a->ip2[0] = htonl(a_ip1 - 1);
    } else {
        goto error;
    }

    return 0;

error:
    return -1;
}

int DetectAddressGroupJoinIPv4(DetectAddressGroup *target, DetectAddressGroup *source) {
    if (ntohl(source->ad->ip[0]) < ntohl(target->ad->ip[0]))
        target->ad->ip[0] = source->ad->ip[0];

    if (ntohl(source->ad->ip2[0]) > ntohl(target->ad->ip2[0]))
        target->ad->ip2[0] = source->ad->ip2[0];

    return 0;
}

