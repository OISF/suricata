/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-address.h"

int AddressCmpIPv4(DetectAddressData *a, DetectAddressData *b) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->ip2[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->ip2[0]);

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

    printf("a->ip[0] %u, a->ip2[0] %u\n", ntohl(a->ip[0]), ntohl(a->ip2[0]));
    DetectAddressDataPrint(a);
    printf("b->ip[0] %u, b->ip2[0] %u\n", ntohl(b->ip[0]), ntohl(b->ip2[0]));
    DetectAddressDataPrint(b);
    printf ("ADDRESS_ER\n");
    return ADDRESS_ER;
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
int AddressCutIPv4(DetectAddressData *a, DetectAddressData *b, DetectAddressData **c) {
    u_int32_t a_ip1 = ntohl(a->ip[0]);
    u_int32_t a_ip2 = ntohl(a->ip2[0]);
    u_int32_t b_ip1 = ntohl(b->ip[0]);
    u_int32_t b_ip2 = ntohl(b->ip2[0]);

    /* default to NULL */
    *c = NULL;

    int r = AddressCmp(a,b);
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
        tmp_c = malloc(sizeof(DetectAddressData));
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
        tmp_c = malloc(sizeof(DetectAddressData));
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
            tmp_c = malloc(sizeof(DetectAddressData));
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
            tmp_c = malloc(sizeof(DetectAddressData));
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



