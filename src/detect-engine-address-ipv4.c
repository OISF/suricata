/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * XXX we need to unit test the hell out of this code
 */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-engine-address.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-port.h"

int DetectAddressCmpIPv4(DetectAddress *a, DetectAddress *b) {
    uint32_t a_ip1 = ntohl(a->ip[0]);
    uint32_t a_ip2 = ntohl(a->ip2[0]);
    uint32_t b_ip1 = ntohl(b->ip[0]);
    uint32_t b_ip2 = ntohl(b->ip2[0]);

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
int DetectAddressCutIPv4(DetectEngineCtx *de_ctx, DetectAddress *a, DetectAddress *b, DetectAddress **c) {
    uint32_t a_ip1 = ntohl(a->ip[0]);
    uint32_t a_ip2 = ntohl(a->ip2[0]);
    uint32_t b_ip1 = ntohl(b->ip[0]);
    uint32_t b_ip2 = ntohl(b->ip2[0]);
    DetectPort *port = NULL;
    DetectAddress *tmp = NULL;

    /* default to NULL */
    *c = NULL;

    int r = DetectAddressCmpIPv4(a,b);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        printf("we shouldn't be here\n");
        goto error;
    }

    /* get a place to temporary put sigs lists */
    tmp = DetectAddressInit();
    if (tmp == NULL) {
        goto error;
    }

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    if (r == ADDRESS_LE) {
#ifdef DBG
        printf("DetectAddressCutIPv4: r == ADDRESS_LE\n");
#endif
        a->ip[0]  = htonl(a_ip1);
        a->ip2[0] = htonl(b_ip1 - 1);

        b->ip[0]  = htonl(b_ip1);
        b->ip2[0] = htonl(a_ip2);

        DetectAddress *tmp_c;
        tmp_c = DetectAddressInit();
        if (tmp_c == NULL) {
            goto error;
        }

        tmp_c->family  = AF_INET;
        tmp_c->ip[0]   = htonl(a_ip2 + 1);
        tmp_c->ip2[0]  = htonl(b_ip2);
        *c = tmp_c;

        if (de_ctx != NULL) {
            SigGroupHeadCopySigs(de_ctx, b->sh,&tmp_c->sh);
            SigGroupHeadCopySigs(de_ctx, a->sh,&b->sh);

            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx, &tmp_c->port, port);
            }
            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx, &b->port, port);
            }

            tmp_c->cnt += b->cnt;
            b->cnt += a->cnt;
        }

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_GE) {
#ifdef DBG
        printf("DetectAddressCutIPv4: r == ADDRESS_GE\n");
#endif
        a->ip[0]   = htonl(b_ip1);
        a->ip2[0] = htonl(a_ip1 - 1);

        b->ip[0]   = htonl(a_ip1);
        b->ip2[0] = htonl(b_ip2);

        DetectAddress *tmp_c;
        tmp_c = DetectAddressInit();
        if (tmp_c == NULL) {
            goto error;
        }

        tmp_c->family = AF_INET;
        tmp_c->ip[0]  = htonl(b_ip2 + 1);
        tmp_c->ip2[0] = htonl(a_ip2);
        *c = tmp_c;

        if (de_ctx != NULL) {
            /* 'a' gets clean and then 'b' sigs
             * 'b' gets clean, then 'a' then 'b' sigs
             * 'c' gets 'a' sigs */
            SigGroupHeadCopySigs(de_ctx, a->sh, &tmp->sh); /* store old a list */
            SigGroupHeadClearSigs(a->sh); /* clean a list */
            SigGroupHeadCopySigs(de_ctx, tmp->sh, &tmp_c->sh); /* copy old b to c */
            SigGroupHeadCopySigs(de_ctx, b->sh, &a->sh); /* copy old b to a */
            SigGroupHeadCopySigs(de_ctx, tmp->sh, &b->sh); /* prepend old a before b */
            SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx, &tmp->port, port);
            }
            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx, &a->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx, &b->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx, &tmp_c->port, port);
            }

            tmp->cnt += a->cnt;
            a->cnt = 0;
            tmp_c->cnt += tmp->cnt;
            a->cnt += b->cnt;
            b->cnt += tmp->cnt;
            tmp->cnt = 0;
        }

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
        printf("DetectAddressCutIPv4: r == ADDRESS_ES\n");
#endif
        if (a_ip1 == b_ip1) {
#ifdef DBG
            printf("DetectAddressCutIPv4: 1\n");
#endif
            a->ip[0]   = htonl(a_ip1);
            a->ip2[0] = htonl(a_ip2);

            b->ip[0]   = htonl(a_ip2 + 1);
            b->ip2[0] = htonl(b_ip2);

            if (de_ctx != NULL) {
                /* 'b' overlaps 'a' so 'a' needs the 'b' sigs */
                SigGroupHeadCopySigs(de_ctx, b->sh, &a->sh);

                for (port = b->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &a->port, port);
                }
                a->cnt += b->cnt;
            }
        } else if (a_ip2 == b_ip2) {
#ifdef DBG
            printf("DetectAddressCutIPv4: 2\n");
#endif
            a->ip[0]   = htonl(b_ip1);
            a->ip2[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->ip2[0] = htonl(a_ip2);

            if (de_ctx != NULL) {
                /* 'a' overlaps 'b' so 'b' needs the 'a' sigs */
                SigGroupHeadCopySigs(de_ctx, a->sh, &tmp->sh);
                SigGroupHeadClearSigs(a->sh);
                SigGroupHeadCopySigs(de_ctx, b->sh, &a->sh);
                SigGroupHeadCopySigs(de_ctx, tmp->sh, &b->sh);
                SigGroupHeadClearSigs(tmp->sh);

                for (port = a->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &tmp->port, a->port);
                }
                for (port = b->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &a->port, port);
                }
                for (port = tmp->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &b->port, port);
                }
                tmp->cnt += a->cnt;
                a->cnt = 0;
                a->cnt += b->cnt;
                b->cnt += tmp->cnt;
                tmp->cnt = 0;
            }
        } else {
#ifdef DBG
            printf("3\n");
#endif
            a->ip[0]   = htonl(b_ip1);
            a->ip2[0] = htonl(a_ip1 - 1);

            b->ip[0]   = htonl(a_ip1);
            b->ip2[0] = htonl(a_ip2);

            DetectAddress *tmp_c;
            tmp_c = DetectAddressInit();
            if (tmp_c == NULL) {
                goto error;
            }

            tmp_c->family  = AF_INET;
            tmp_c->ip[0]   = htonl(a_ip2 + 1);
            tmp_c->ip2[0] = htonl(b_ip2);
            *c = tmp_c;

            if (de_ctx != NULL) {
                /* 'a' gets clean and then 'b' sigs
                 * 'b' gets clean, then 'a' then 'b' sigs
                 * 'c' gets 'b' sigs */
                SigGroupHeadCopySigs(de_ctx, a->sh, &tmp->sh); /* store old a list */
                SigGroupHeadClearSigs(a->sh); /* clean a list */
                SigGroupHeadCopySigs(de_ctx, b->sh, &tmp_c->sh); /* copy old b to c */
                SigGroupHeadCopySigs(de_ctx, b->sh, &a->sh); /* copy old b to a */
                SigGroupHeadCopySigs(de_ctx, tmp->sh, &b->sh); /* prepend old a before b */
                SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

                for (port = a->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &tmp->port, port);
                }
                for (port = b->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &tmp_c->port, port);
                }
                for (port = b->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &a->port, port);
                }
                for (port = tmp->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &b->port, port);
                }
                tmp->cnt += a->cnt;
                a->cnt = 0;
                tmp_c->cnt += b->cnt;
                a->cnt += b->cnt;
                b->cnt += tmp->cnt;
                tmp->cnt = 0;
            }
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
        printf("DetectAddressCutIPv4: r == ADDRESS_EB\n");
#endif
        if (a_ip1 == b_ip1) {
#ifdef DBG
            printf("DetectAddressCutIPv4: 1\n");
#endif
            a->ip[0]   = htonl(b_ip1);
            a->ip2[0] = htonl(b_ip2);

            b->ip[0]   = htonl(b_ip2 + 1);
            b->ip2[0] = htonl(a_ip2);

            if (de_ctx != NULL) {
                /* 'b' overlaps 'a' so a needs the 'b' sigs */
                SigGroupHeadCopySigs(de_ctx, b->sh, &tmp->sh);
                SigGroupHeadClearSigs(b->sh);
                SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh);
                SigGroupHeadCopySigs(de_ctx, tmp->sh, &a->sh);
                SigGroupHeadClearSigs(tmp->sh);

                for (port = b->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &tmp->port, b->port);
                }
                for (port = a->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &b->port, port);
                }
                for (port = tmp->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &a->port, port);
                }
                tmp->cnt += b->cnt;
                b->cnt = 0;
                b->cnt += a->cnt;
                a->cnt += tmp->cnt;
                tmp->cnt = 0;
            }
        } else if (a_ip2 == b_ip2) {
#ifdef DBG
            printf("DetectAddressCutIPv4: 2\n");
#endif
            a->ip[0]   = htonl(a_ip1);
            a->ip2[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->ip2[0] = htonl(b_ip2);

            if (de_ctx != NULL) {
                /* 'a' overlaps 'b' so a needs the 'a' sigs */
                SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh);

                for (port = a->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &b->port, port);
                }

                b->cnt += a->cnt;
            }
        } else {
#ifdef DBG
            printf("DetectAddressCutIPv4: 3\n");
#endif
            a->ip[0]   = htonl(a_ip1);
            a->ip2[0] = htonl(b_ip1 - 1);

            b->ip[0]   = htonl(b_ip1);
            b->ip2[0] = htonl(b_ip2);

            DetectAddress *tmp_c;
            tmp_c = DetectAddressInit();
            if (tmp_c == NULL) {
                goto error;
            }

            tmp_c->family  = AF_INET;
            tmp_c->ip[0]   = htonl(b_ip2 + 1);
            tmp_c->ip2[0] = htonl(a_ip2);
            *c = tmp_c;

            if (de_ctx != NULL) {
                /* 'a' stays the same wrt sigs
                 * 'b' keeps it's own sigs and gets a's sigs prepended
                 * 'c' gets 'a' sigs */
                SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh);
                SigGroupHeadCopySigs(de_ctx, a->sh, &tmp_c->sh);

                for (port = a->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &b->port, port);
                }
                for (port = a->port; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx, &tmp_c->port, port);
                }

                b->cnt += a->cnt;
                tmp_c->cnt += a->cnt;
            }
        }
    }

    if (tmp != NULL)
        DetectAddressFree(tmp);
    return 0;

error:
    if (tmp != NULL)
        DetectAddressFree(tmp);
    return -1;
}

/** \brief check if the address group list covers the complete
 *         IPv4 IP space.
 *  \retval 0 no
 *  \retval 1 yes
 */
int DetectAddressIsCompleteIPSpaceIPv4(DetectAddress *ag) {
    uint32_t next_ip = 0;

    if (ag == NULL)
        return 0;

    /* if we don't start with 0.0.0.0 we know we're good */
    if (ntohl(ag->ip[0]) != 0x00000000)
        return 0;

    /* if we're ending with 255.255.255.255 while we know
       we started with 0.0.0.0 it's the complete space */
    if (ntohl(ag->ip2[0]) == 0xFFFFFFFF)
        return 1;

    next_ip = htonl(ntohl(ag->ip2[0]) + 1);
    ag = ag->next;

    for ( ; ag != NULL; ag = ag->next) {
        if (ag == NULL)
            return 0;

        if (ag->ip[0] != next_ip)
            return 0;

        if (ntohl(ag->ip2[0]) == 0xFFFFFFFF)
            return 1;

        next_ip = htonl(ntohl(ag->ip2[0]) + 1);
    }

    return 0;
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
int DetectAddressCutNotIPv4(DetectAddress *a, DetectAddress **b) {
    uint32_t a_ip1 = ntohl(a->ip[0]);
    uint32_t a_ip2 = ntohl(a->ip2[0]);

    /* default to NULL */
    *b = NULL;

    if (a_ip1 != 0x00000000 && a_ip2 != 0xFFFFFFFF) {
        a->ip[0]  = htonl(0x00000000);
        a->ip2[0] = htonl(a_ip1 - 1);

        DetectAddress *tmp_b = DetectAddressInit();
        if (tmp_b == NULL) {
            goto error;
        }
        tmp_b->family = AF_INET;
        tmp_b->ip[0]  = htonl(a_ip2 + 1);
        tmp_b->ip2[0] = htonl(0xFFFFFFFF);
        *b = tmp_b;

    } else if (a_ip1 == 0x00000000 && a_ip2 != 0xFFFFFFFF) {
        a->ip[0] = htonl(a_ip2 + 1);
        a->ip2[0] = htonl(0xFFFFFFFF);

    } else if (a_ip1 != 0x00000000 && a_ip2 == 0xFFFFFFFF) {
        a->ip[0] = htonl(0x00000000);
        a->ip2[0] = htonl(a_ip1 - 1);
    } else {
        goto error;
    }

    return 0;

error:
    return -1;
}

int DetectAddressJoinIPv4(DetectEngineCtx *de_ctx, DetectAddress *target, DetectAddress *source) {
    if (ntohl(source->ip[0]) < ntohl(target->ip[0]))
        target->ip[0] = source->ip[0];

    if (ntohl(source->ip2[0]) > ntohl(target->ip2[0]))
        target->ip2[0] = source->ip2[0];

    return 0;
}

