/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * XXX unit test the join code
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


/* return: 1 lt, 0 not lt */
int AddressIPv6Lt(uint32_t *a, uint32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (ntohl(a[i]) < ntohl(b[i]))
            return 1;
        if (ntohl(a[i]) > ntohl(b[i]))
            break;
    }

    return 0;
}

/* return: 1 gt, 0 not gt */
int AddressIPv6Gt(uint32_t *a, uint32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (ntohl(a[i]) > ntohl(b[i]))
            return 1;
        if (ntohl(a[i]) < ntohl(b[i]))
            break;
    }

    return 0;
}

/* return: 1 eq, 0 not eq */
int AddressIPv6Eq(uint32_t *a, uint32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

/* return: 1 le, 0 not le */
int AddressIPv6Le(uint32_t *a, uint32_t *b) {

    if (AddressIPv6Eq(a,b) == 1)
        return 1;
    if (AddressIPv6Lt(a,b) == 1)
        return 1;

    return 0;
}

/* return: 1 ge, 0 not ge */
int AddressIPv6Ge(uint32_t *a, uint32_t *b) {

    if (AddressIPv6Eq(a,b) == 1)
        return 1;
    if (AddressIPv6Gt(a,b) == 1)
        return 1;

    return 0;
}

int DetectAddressCmpIPv6(DetectAddress *a, DetectAddress *b) {
    /* ADDRESS_EQ */
    if (AddressIPv6Eq(a->ip, b->ip) == 1 &&
        AddressIPv6Eq(a->ip2, b->ip2) == 1) {
        //printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    /* ADDRESS_ES */
    } else if (AddressIPv6Ge(a->ip, b->ip) == 1 &&
               AddressIPv6Le(a->ip, b->ip2) == 1 &&
               AddressIPv6Le(a->ip2, b->ip2) == 1) {
        //printf("ADDRESS_ES\n");
        return ADDRESS_ES;
    /* ADDRESS_EB */
    } else if (AddressIPv6Le(a->ip, b->ip) == 1 &&
               AddressIPv6Ge(a->ip2, b->ip2) == 1) {
        //printf("ADDRESS_EB\n");
        return ADDRESS_EB;
    } else if (AddressIPv6Lt(a->ip, b->ip) == 1 &&
               AddressIPv6Lt(a->ip2, b->ip2) == 1 &&
               AddressIPv6Ge(a->ip2, b->ip) == 1) {
        //printf("ADDRESS_LE\n");
        return ADDRESS_LE;
    } else if (AddressIPv6Lt(a->ip, b->ip) == 1 &&
               AddressIPv6Lt(a->ip2, b->ip2) == 1) {
        //printf("ADDRESS_LT\n");
        return ADDRESS_LT;
    } else if (AddressIPv6Gt(a->ip, b->ip) == 1 &&
               AddressIPv6Le(a->ip, b->ip2) == 1 &&
               AddressIPv6Gt(a->ip2, b->ip2) == 1) {
        //printf("ADDRESS_GE\n");
        return ADDRESS_GE;
    } else if (AddressIPv6Gt(a->ip, b->ip2) == 1) {
        //printf("ADDRESS_GT\n");
        return ADDRESS_GT;
    } else {
        /* should be unreachable */
        printf("Internal Error: should be unreachable\n");
    }

//    printf ("ADDRESS_ER\n");
    return ADDRESS_ER;
}

/* address is in host order! */
static void AddressCutIPv6CopySubOne(uint32_t *a, uint32_t *b) {
    uint32_t t = a[3];

    b[0] = a[0];
    b[1] = a[1];
    b[2] = a[2];
    b[3] = a[3];

    //printf("start: 0x%08X 0x%08X 0x%08X 0x%08X\n", a[0], a[1], a[2], a[3]);
    b[3] --;
    if (b[3] > t) {
        t = b[2];
        b[2] --;
        if (b[2] > t) {
            t = b[1];
            b[1] --;
            if (b[1] > t) {
                b[0] --;
            }
        }
    }

    b[0] = htonl(b[0]);
    b[1] = htonl(b[1]);
    b[2] = htonl(b[2]);
    b[3] = htonl(b[3]);

    //printf("result: 0x%08X 0x%08X 0x%08X 0x%08X\n", a[0], a[1], a[2], a[3]);
}

static void AddressCutIPv6CopyAddOne(uint32_t *a, uint32_t *b) {
    uint32_t t = a[3];

    b[0] = a[0];
    b[1] = a[1];
    b[2] = a[2];
    b[3] = a[3];

    //printf("start: 0x%08X 0x%08X 0x%08X 0x%08X\n", a[0], a[1], a[2], a[3]);
    b[3] ++;
    if (b[3] < t) {
        t = b[2];
        b[2] ++;
        if (b[2] < t) {
            t = b[1];
            b[1] ++;
            if (b[1] < t) {
                b[0] ++;
            }
        }
    }

    b[0] = htonl(b[0]);
    b[1] = htonl(b[1]);
    b[2] = htonl(b[2]);
    b[3] = htonl(b[3]);

    //printf("result: 0x%08X 0x%08X 0x%08X 0x%08X\n", a[0], a[1], a[2], a[3]);
}

static void AddressCutIPv6Copy(uint32_t *a, uint32_t *b) {
    b[0] = htonl(a[0]);
    b[1] = htonl(a[1]);
    b[2] = htonl(a[2]);
    b[3] = htonl(a[3]);
}

int DetectAddressCutIPv6(DetectEngineCtx *de_ctx, DetectAddress *a, DetectAddress *b, DetectAddress **c) {
    uint32_t a_ip1[4] = { ntohl(a->ip[0]),  ntohl(a->ip[1]),
                           ntohl(a->ip[2]),  ntohl(a->ip[3]) };
    uint32_t a_ip2[4] = { ntohl(a->ip2[0]), ntohl(a->ip2[1]),
                           ntohl(a->ip2[2]), ntohl(a->ip2[3]) };
    uint32_t b_ip1[4] = { ntohl(b->ip[0]),  ntohl(b->ip[1]),
                           ntohl(b->ip[2]),  ntohl(b->ip[3]) };
    uint32_t b_ip2[4] = { ntohl(b->ip2[0]), ntohl(b->ip2[1]),
                           ntohl(b->ip2[2]), ntohl(b->ip2[3]) };
    DetectPort *port = NULL;
    DetectAddress *tmp = NULL;

    /* default to NULL */
    *c = NULL;

    int r = DetectAddressCmpIPv6(a,b);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        goto error;
    }

    /* get a place to temporary put sigs lists */
    tmp = DetectAddressInit();
    if (tmp == NULL) {
        goto error;
    }
    memset(tmp,0,sizeof(DetectAddress));

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    if (r == ADDRESS_LE) {
        AddressCutIPv6Copy(a_ip1, a->ip);
        AddressCutIPv6CopySubOne(b_ip1, a->ip2);

        AddressCutIPv6Copy(b_ip1, b->ip);
        AddressCutIPv6Copy(a_ip2, b->ip2);

        DetectAddress *tmp_c;
        tmp_c = DetectAddressInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET6;
        AddressCutIPv6CopyAddOne(a_ip2, tmp_c->ip);
        AddressCutIPv6Copy(b_ip2, tmp_c->ip2);
        *c = tmp_c;

        SigGroupHeadCopySigs(de_ctx, b->sh, &tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh); /* copy old b to a */

        for (port = b->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx, &tmp_c->port, port);
        }
        for (port = a->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx, &b->port, port);
        }

        tmp_c->cnt += b->cnt;
        b->cnt += a->cnt;

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_GE) {
        AddressCutIPv6Copy(b_ip1, a->ip);
        AddressCutIPv6CopySubOne(a_ip1, a->ip2);

        AddressCutIPv6Copy(a_ip1, b->ip);
        AddressCutIPv6Copy(b_ip2, b->ip2);

        DetectAddress *tmp_c;
        tmp_c = DetectAddressInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET6;
        AddressCutIPv6CopyAddOne(b_ip2, tmp_c->ip);
        AddressCutIPv6Copy(a_ip2, tmp_c->ip2);
        *c = tmp_c;

        /* 'a' gets clean and then 'b' sigs
         * 'b' gets clean, then 'a' then 'b' sigs
         * 'c' gets 'a' sigs */
        SigGroupHeadCopySigs(de_ctx, a->sh, &tmp->sh); /* store old a list */
        SigGroupHeadClearSigs(a->sh); /* clean a list */
        SigGroupHeadCopySigs(de_ctx, tmp->sh, &tmp_c->sh); /* copy old b to c */
        SigGroupHeadCopySigs(de_ctx, b->sh,&a->sh); /* copy old b to a */
        SigGroupHeadCopySigs(de_ctx, tmp->sh, &b->sh); /* prepend old a before b */

        SigGroupHeadClearSigs(tmp->sh); /* clean tmp list */

        for (port = a->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx,&tmp->port, port);
        }
        for (port = b->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx,&a->port, port);
        }
        for (port = tmp->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx,&b->port, port);
        }
        for (port = tmp->port; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx,&tmp_c->port, port);
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
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    } else if (r == ADDRESS_ES) {
        if (AddressIPv6Eq(a_ip1,b_ip1) == 1) {
            AddressCutIPv6Copy(a_ip1, a->ip);
            AddressCutIPv6Copy(a_ip2, a->ip2);

            AddressCutIPv6CopyAddOne(a_ip2, b->ip);
            AddressCutIPv6Copy(b_ip2, b->ip2);

            /* 'b' overlaps 'a' so 'a' needs the 'b' sigs */
            SigGroupHeadCopySigs(de_ctx, b->sh,&a->sh);

            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&a->port, port);
            }
            a->cnt += b->cnt;

        } else if (AddressIPv6Eq(a_ip2, b_ip2) == 1) {
            AddressCutIPv6Copy(b_ip1, a->ip);
            AddressCutIPv6CopySubOne(a_ip1, a->ip2);

            AddressCutIPv6Copy(a_ip1, b->ip);
            AddressCutIPv6Copy(a_ip2, b->ip2);

            /* 'a' overlaps 'b' so 'b' needs the 'a' sigs */
            SigGroupHeadCopySigs(de_ctx, a->sh, &tmp->sh);
            SigGroupHeadClearSigs(a->sh);
            SigGroupHeadCopySigs(de_ctx, b->sh, &a->sh);
            SigGroupHeadCopySigs(de_ctx, tmp->sh, &b->sh);
            SigGroupHeadClearSigs(tmp->sh);

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&tmp->port, a->port);
            }
            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&a->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&b->port, port);
            }
            tmp->cnt += a->cnt;
            a->cnt = 0;
            a->cnt += b->cnt;
            b->cnt += tmp->cnt;
            tmp->cnt = 0;
        } else {
            AddressCutIPv6Copy(b_ip1, a->ip);
            AddressCutIPv6CopySubOne(a_ip1, a->ip2);

            AddressCutIPv6Copy(a_ip1, b->ip);
            AddressCutIPv6Copy(a_ip2, b->ip2);

            DetectAddress *tmp_c;
            tmp_c = DetectAddressInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET6;
            AddressCutIPv6CopyAddOne(a_ip2, tmp_c->ip);
            AddressCutIPv6Copy(b_ip2, tmp_c->ip2);
            *c = tmp_c;

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
                DetectPortInsertCopy(de_ctx,&tmp->port, port);
            }
            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&tmp_c->port, port);
            }
            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&a->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&b->port, port);
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
     * part a: a_ip1 <-> b_ip2 - 1
     * part b: b_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_EB) {
        if (AddressIPv6Eq(a_ip1, b_ip1) == 1) {
            AddressCutIPv6Copy(b_ip1, a->ip);
            AddressCutIPv6Copy(b_ip2, a->ip2);

            AddressCutIPv6CopyAddOne(b_ip2, b->ip);
            AddressCutIPv6Copy(a_ip2, b->ip2);

            /* 'b' overlaps 'a' so a needs the 'b' sigs */
            SigGroupHeadCopySigs(de_ctx, b->sh, &tmp->sh);
            SigGroupHeadClearSigs(b->sh);
            SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh);
            SigGroupHeadCopySigs(de_ctx, tmp->sh, &a->sh);
            SigGroupHeadClearSigs(tmp->sh);

            for (port = b->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&tmp->port, b->port);
            }
            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&b->port, port);
            }
            for (port = tmp->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&a->port, port);
            }
            tmp->cnt += b->cnt;
            b->cnt = 0;
            b->cnt += a->cnt;
            a->cnt += tmp->cnt;
            tmp->cnt = 0;
        } else if (AddressIPv6Eq(a_ip2, b_ip2) == 1) {
            AddressCutIPv6Copy(a_ip1, a->ip);
            AddressCutIPv6CopySubOne(b_ip1, a->ip2);

            AddressCutIPv6Copy(b_ip1, b->ip);
            AddressCutIPv6Copy(b_ip2, b->ip2);

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh);

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&b->port, port);
            }

            b->cnt += a->cnt;
        } else {
            AddressCutIPv6Copy(a_ip1, a->ip);
            AddressCutIPv6CopySubOne(b_ip1, a->ip2);

            AddressCutIPv6Copy(b_ip1, b->ip);
            AddressCutIPv6Copy(b_ip2, b->ip2);

            DetectAddress *tmp_c;
            tmp_c = DetectAddressInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET6;
            AddressCutIPv6CopyAddOne(b_ip2, tmp_c->ip);
            AddressCutIPv6Copy(a_ip2, tmp_c->ip2);
            *c = tmp_c;

            /* 'a' stays the same wrt sigs
             * 'b' keeps it's own sigs and gets a's sigs prepended
             * 'c' gets 'a' sigs */
            SigGroupHeadCopySigs(de_ctx, a->sh, &b->sh);
            SigGroupHeadCopySigs(de_ctx, a->sh, &tmp_c->sh);

            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&b->port, port);
            }
            for (port = a->port; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&tmp_c->port, port);
            }

            b->cnt += a->cnt;
            tmp_c->cnt += a->cnt;
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
#if 0
int DetectAddressCutIPv6(DetectAddressData *a, DetectAddressData *b, DetectAddressData **c) {
    uint32_t a_ip1[4] = { ntohl(a->ip[0]), ntohl(a->ip[1]), ntohl(a->ip[2]), ntohl(a->ip[3]) };
    uint32_t a_ip2[4] = { ntohl(a->ip2[0]), ntohl(a->ip2[1]), ntohl(a->ip2[2]), ntohl(a->ip2[3]) };
    uint32_t b_ip1[4] = { ntohl(b->ip[0]), ntohl(b->ip[1]), ntohl(b->ip[2]), ntohl(b->ip[3]) };
    uint32_t b_ip2[4] = { ntohl(b->ip2[0]), ntohl(b->ip2[1]), ntohl(b->ip2[2]), ntohl(b->ip2[3]) };

    /* default to NULL */
    *c = NULL;

    int r = DetectAddressCmpIPv6(a,b);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        goto error;
    }

    /* we have 3 parts: [aaa[abab]bbb]
     * part a: a_ip1 <-> b_ip1 - 1
     * part b: b_ip1 <-> a_ip2
     * part c: a_ip2 + 1 <-> b_ip2
     */
    if (r == ADDRESS_LE) {
        AddressCutIPv6Copy(a_ip1, a->ip);
        AddressCutIPv6CopySubOne(b_ip1, a->ip2);

        AddressCutIPv6Copy(b_ip1, b->ip);
        AddressCutIPv6Copy(a_ip2, b->ip2);

        DetectAddressData *tmp_c;
        tmp_c = DetectAddressDataInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET6;
        AddressCutIPv6CopyAddOne(a_ip2, tmp_c->ip);
        AddressCutIPv6Copy(b_ip2, tmp_c->ip2);
        *c = tmp_c;

    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_GE) {
        AddressCutIPv6Copy(b_ip1, a->ip);
        AddressCutIPv6CopySubOne(a_ip1, a->ip2);

        AddressCutIPv6Copy(a_ip1, b->ip);
        AddressCutIPv6Copy(b_ip2, b->ip2);

        DetectAddressData *tmp_c;
        tmp_c = DetectAddressDataInit();
        if (tmp_c == NULL) {
            goto error;
        }
        tmp_c->family  = AF_INET6;
        AddressCutIPv6CopyAddOne(b_ip2, tmp_c->ip);
        AddressCutIPv6Copy(a_ip2, tmp_c->ip2);
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
        if (AddressIPv6Eq(a_ip1,b_ip1) == 1) {
            AddressCutIPv6Copy(a_ip1, a->ip);
            AddressCutIPv6Copy(a_ip2, a->ip2);

            AddressCutIPv6CopyAddOne(a_ip2, b->ip);
            AddressCutIPv6Copy(b_ip2, b->ip2);
        } else if (AddressIPv6Eq(a_ip2, b_ip2) == 1) {
            AddressCutIPv6Copy(b_ip1, a->ip);
            AddressCutIPv6CopySubOne(a_ip1, a->ip2);

            AddressCutIPv6Copy(a_ip1, b->ip);
            AddressCutIPv6Copy(a_ip2, b->ip2);
        } else {
            AddressCutIPv6Copy(b_ip1, a->ip);
            AddressCutIPv6CopySubOne(a_ip1, a->ip2);

            AddressCutIPv6Copy(a_ip1, b->ip);
            AddressCutIPv6Copy(a_ip2, b->ip2);

            DetectAddressData *tmp_c;
            tmp_c = DetectAddressDataInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET6;
            AddressCutIPv6CopyAddOne(a_ip2, tmp_c->ip);
            AddressCutIPv6Copy(b_ip2, tmp_c->ip2);
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
        if (AddressIPv6Eq(a_ip1, b_ip1) == 1) {
            AddressCutIPv6Copy(b_ip1, a->ip);
            AddressCutIPv6Copy(b_ip2, a->ip2);

            AddressCutIPv6CopyAddOne(b_ip2, b->ip);
            AddressCutIPv6Copy(a_ip2, b->ip2);
        } else if (AddressIPv6Eq(a_ip2, b_ip2) == 1) {
            AddressCutIPv6Copy(a_ip1, a->ip);
            AddressCutIPv6CopySubOne(b_ip1, a->ip2);

            AddressCutIPv6Copy(b_ip1, b->ip);
            AddressCutIPv6Copy(b_ip2, b->ip2);
        } else {
            AddressCutIPv6Copy(a_ip1, a->ip);
            AddressCutIPv6CopySubOne(b_ip1, a->ip2);

            AddressCutIPv6Copy(b_ip1, b->ip);
            AddressCutIPv6Copy(b_ip2, b->ip2);

            DetectAddressData *tmp_c;
            tmp_c = DetectAddressDataInit();
            if (tmp_c == NULL) {
                goto error;
            }
            tmp_c->family  = AF_INET6;
            AddressCutIPv6CopyAddOne(b_ip2, tmp_c->ip);
            AddressCutIPv6Copy(a_ip2, tmp_c->ip2);
            *c = tmp_c;
        }
    }

    return 0;

error:
    return -1;
}
#endif
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
int DetectAddressCutNotIPv6(DetectAddress *a, DetectAddress **b) {
    uint32_t a_ip1[4] = { ntohl(a->ip[0]), ntohl(a->ip[1]), ntohl(a->ip[2]), ntohl(a->ip[3]) };
    uint32_t a_ip2[4] = { ntohl(a->ip2[0]), ntohl(a->ip2[1]), ntohl(a->ip2[2]), ntohl(a->ip2[3]) };
    uint32_t ip_nul[4] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
    uint32_t ip_max[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };

    /* default to NULL */
    *b = NULL;

    if (a_ip1[0] != 0x00000000 && a_ip1[1] != 0x00000000 &&
        a_ip1[2] != 0x00000000 && a_ip1[3] != 0x00000000 &&
        a_ip2[0] != 0xFFFFFFFF && a_ip2[1] != 0xFFFFFFFF &&
        a_ip2[2] != 0xFFFFFFFF && a_ip2[3] != 0xFFFFFFFF)
    {
        AddressCutIPv6Copy(ip_nul, a->ip);
        AddressCutIPv6CopySubOne(a_ip1, a->ip2);

        DetectAddress *tmp_b = DetectAddressInit();
        if (tmp_b == NULL) {
            goto error;
        }
        tmp_b->family  = AF_INET6;
        AddressCutIPv6CopyAddOne(a_ip2, tmp_b->ip);
        AddressCutIPv6Copy(ip_max, tmp_b->ip2);
        *b = tmp_b;

    } else if (a_ip1[0] == 0x00000000 && a_ip1[1] == 0x00000000 &&
        a_ip1[2] == 0x00000000 && a_ip1[3] == 0x00000000 &&
        a_ip2[0] != 0xFFFFFFFF && a_ip2[1] != 0xFFFFFFFF &&
        a_ip2[2] != 0xFFFFFFFF && a_ip2[3] != 0xFFFFFFFF)
    {
        AddressCutIPv6CopyAddOne(a_ip2, a->ip);
        AddressCutIPv6Copy(ip_max, a->ip2);

    } else if (a_ip1[0] != 0x00000000 && a_ip1[1] != 0x00000000 &&
        a_ip1[2] != 0x00000000 && a_ip1[3] != 0x00000000 &&
        a_ip2[0] == 0xFFFFFFFF && a_ip2[1] == 0xFFFFFFFF &&
        a_ip2[2] == 0xFFFFFFFF && a_ip2[3] == 0xFFFFFFFF)
    {
        AddressCutIPv6Copy(ip_nul, a->ip);
        AddressCutIPv6CopyAddOne(a_ip2, a->ip2);

    } else {
        goto error;
    }

    return 0;

error:
    return -1;
}

int DetectAddressJoinIPv6(DetectEngineCtx *de_ctx, DetectAddress *target, DetectAddress *source) {
    if (AddressIPv6Lt(source->ip,target->ip)) {
        target->ip[0] = source->ip[0];
        target->ip[1] = source->ip[1];
        target->ip[2] = source->ip[2];
        target->ip[3] = source->ip[3];
    }

    if (AddressIPv6Gt(source->ip,target->ip)) {
        target->ip2[0] = source->ip2[0];
        target->ip2[1] = source->ip2[1];
        target->ip2[2] = source->ip2[2];
        target->ip2[3] = source->ip2[3];
    }

    return 0;
}

/* TESTS */

#ifdef UNITTESTS
int AddressTestIPv6Gt01 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Gt02 (void) {
    int result = 0;

    uint32_t a[4] = { 0, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Gt03 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Gt04 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 5 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Lt01 (void) {
    int result = 0;

    uint32_t a[4] = { 0, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Lt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Lt02 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Lt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Lt03 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Lt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Lt04 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Lt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Eq01 (void) {
    int result = 0;

    uint32_t a[4] = { 0, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Eq02 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Eq03 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Eq(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Eq04 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Le01 (void) {
    int result = 0;

    uint32_t a[4] = { 0, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Le02 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Le(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Le03 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Le04 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Le05 (void) {
    int result = 0;

    uint32_t a[4];
    uint32_t b[4];
    struct in6_addr in6;

    inet_pton(AF_INET6, "1999:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &in6);
    memcpy(&a, &in6.s6_addr, sizeof(in6.s6_addr));

    inet_pton(AF_INET6, "2000::0", &in6);
    memcpy(&b, &in6.s6_addr, sizeof(in6.s6_addr));

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Ge01 (void) {
    int result = 0;

    uint32_t a[4] = { 0, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Ge02 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Ge(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Ge03 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Ge(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Ge04 (void) {
    int result = 0;

    uint32_t a[4] = { 1, 2, 3, 4 };
    uint32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Ge05 (void) {
    int result = 0;

    uint32_t a[4];
    uint32_t b[4];
    struct in6_addr in6;

    inet_pton(AF_INET6, "1999:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &in6);
    memcpy(&a, &in6.s6_addr, sizeof(in6.s6_addr));

    inet_pton(AF_INET6, "2000::0", &in6);
    memcpy(&b, &in6.s6_addr, sizeof(in6.s6_addr));

    if (AddressIPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6SubOne01 (void) {
    int result = 0;

    uint32_t a[4], b[4];
    struct in6_addr in6;

    inet_pton(AF_INET6, "2000::1", &in6);
    memcpy(&a, &in6.s6_addr, sizeof(in6.s6_addr));

    a[0] = ntohl(a[0]);
    a[1] = ntohl(a[1]);
    a[2] = ntohl(a[2]);
    a[3] = ntohl(a[3]);

    AddressCutIPv6CopySubOne(a,b);

    if (b[0] == 0x00000020 && b[1] == 0x00000000 &&
        b[2] == 0x00000000 && b[3] == 0x00000000) {
        result = 1;
    }
    return result;
}

int AddressTestIPv6SubOne02 (void) {
    int result = 0;

    uint32_t a[4],b[4];
    struct in6_addr in6;

    inet_pton(AF_INET6, "2000::0", &in6);
    memcpy(&a, &in6.s6_addr, sizeof(in6.s6_addr));

    a[0] = ntohl(a[0]);
    a[1] = ntohl(a[1]);
    a[2] = ntohl(a[2]);
    a[3] = ntohl(a[3]);

    AddressCutIPv6CopySubOne(a,b);

    if (b[0] == 0xffffff1f && b[1] == 0xffffffff &&
        b[2] == 0xffffffff && b[3] == 0xffffffff) {
        result = 1;
    }

    return result;
}
#endif /* UNITTESTS */

void DetectAddressIPv6Tests(void) {
#ifdef UNITTESTS
    UtRegisterTest("AddressTestIPv6Gt01",   AddressTestIPv6Gt01, 1);
    UtRegisterTest("AddressTestIPv6Gt02",   AddressTestIPv6Gt02, 1);
    UtRegisterTest("AddressTestIPv6Gt03",   AddressTestIPv6Gt03, 1);
    UtRegisterTest("AddressTestIPv6Gt04",   AddressTestIPv6Gt04, 1);

    UtRegisterTest("AddressTestIPv6Lt01",   AddressTestIPv6Lt01, 1);
    UtRegisterTest("AddressTestIPv6Lt02",   AddressTestIPv6Lt02, 1);
    UtRegisterTest("AddressTestIPv6Lt03",   AddressTestIPv6Lt03, 1);
    UtRegisterTest("AddressTestIPv6Lt04",   AddressTestIPv6Lt04, 1);

    UtRegisterTest("AddressTestIPv6Eq01",   AddressTestIPv6Eq01, 1);
    UtRegisterTest("AddressTestIPv6Eq02",   AddressTestIPv6Eq02, 1);
    UtRegisterTest("AddressTestIPv6Eq03",   AddressTestIPv6Eq03, 1);
    UtRegisterTest("AddressTestIPv6Eq04",   AddressTestIPv6Eq04, 1);

    UtRegisterTest("AddressTestIPv6Le01",   AddressTestIPv6Le01, 1);
    UtRegisterTest("AddressTestIPv6Le02",   AddressTestIPv6Le02, 1);
    UtRegisterTest("AddressTestIPv6Le03",   AddressTestIPv6Le03, 1);
    UtRegisterTest("AddressTestIPv6Le04",   AddressTestIPv6Le04, 1);
    UtRegisterTest("AddressTestIPv6Le05",   AddressTestIPv6Le05, 1);

    UtRegisterTest("AddressTestIPv6Ge01",   AddressTestIPv6Ge01, 1);
    UtRegisterTest("AddressTestIPv6Ge02",   AddressTestIPv6Ge02, 1);
    UtRegisterTest("AddressTestIPv6Ge03",   AddressTestIPv6Ge03, 1);
    UtRegisterTest("AddressTestIPv6Ge04",   AddressTestIPv6Ge04, 1);
    UtRegisterTest("AddressTestIPv6Ge05",   AddressTestIPv6Ge05, 1);

    UtRegisterTest("AddressTestIPv6SubOne01",   AddressTestIPv6SubOne01, 1);
    UtRegisterTest("AddressTestIPv6SubOne02",   AddressTestIPv6SubOne02, 1);
#endif /* UNITTESTS */
}


