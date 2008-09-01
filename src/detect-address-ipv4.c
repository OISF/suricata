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
#include "detect-siggroup.h"

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

    /* default to NULL */
    *c = NULL;
#ifdef DBG
    printf("a "); DetectAddressDataPrint(a->ad); printf("\n");
    printf("b "); DetectAddressDataPrint(b->ad); printf("\n");
    printf("a sigs: ");
    SigGroupContainer *sgc = a->sh ? a->sh->head : NULL;
    for ( ; sgc != NULL; sgc = sgc->next) printf("%u ",sgc->s->id);
    printf("\nb sigs: ");
    sgc = b->sh ? b->sh->head : NULL;
    for ( ; sgc != NULL; sgc = sgc->next) printf("%u ",sgc->s->id);
    printf("\n");
#endif
    int r = DetectAddressCmpIPv4(a->ad,b->ad);
    if (r != ADDRESS_ES && r != ADDRESS_EB && r != ADDRESS_LE && r != ADDRESS_GE) {
        printf("we shouldn't be here\n");
        goto error;
    }

    /* get a place to temporary put sigs lists */
    DetectAddressGroup *tmp;
    tmp = DetectAddressGroupInit();
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
        printf("cut r == ADDRESS_LE\n");
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

        SigGroupListCopyAppend(b,tmp_c); /* copy old b to c */
        SigGroupListCopyPrepend(a,b); /* copy old b to a */

#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("C "); DetectAddressDataPrint(tmp_c->ad); printf(" ");
for(sg = tmp_c->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
    /* we have 3 parts: [bbb[baba]aaa]
     * part a: b_ip1 <-> a_ip1 - 1
     * part b: a_ip1 <-> b_ip2
     * part c: b_ip2 + 1 <-> a_ip2
     */
    } else if (r == ADDRESS_GE) {
#ifdef DBG
        printf("cut r == ADDRESS_GE\n");
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
        SigGroupListCopyAppend(a,tmp); /* store old a list */
        SigGroupListClean(a->sh); /* clean a list */
        SigGroupListCopyAppend(tmp,tmp_c); /* copy old b to c */
        SigGroupListCopyAppend(b,a); /* copy old b to a */
        SigGroupListCopyPrepend(tmp,b); /* prepend old a before b */

        SigGroupListClean(tmp->sh); /* clean tmp list */
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
        printf("cut r == ADDRESS_ES\n");
#endif
        if (a_ip1 == b_ip1) {
#ifdef DBG
            printf("1\n");
#endif
            a->ad->ip[0]   = htonl(a_ip1);
            a->ad->ip2[0] = htonl(a_ip2);

            b->ad->ip[0]   = htonl(a_ip2 + 1);
            b->ad->ip2[0] = htonl(b_ip2);

            /* 'b' overlaps 'a' so 'a' needs the 'b' sigs */
            SigGroupListCopyAppend(b,a);
#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
        } else if (a_ip2 == b_ip2) {
#ifdef DBG
            printf("2\n");
#endif
            a->ad->ip[0]   = htonl(b_ip1);
            a->ad->ip2[0] = htonl(a_ip1 - 1);

            b->ad->ip[0]   = htonl(a_ip1);
            b->ad->ip2[0] = htonl(a_ip2);

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupListCopyPrepend(a,b);
#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
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
            SigGroupListCopyAppend(a,tmp); /* store old a list */
            SigGroupListClean(a->sh); /* clean a list */
            SigGroupListCopyAppend(b,tmp_c); /* copy old b to c */
            SigGroupListCopyAppend(b,a); /* copy old b to a */
            SigGroupListCopyPrepend(tmp,b); /* prepend old a before b */

            SigGroupListClean(tmp->sh); /* clean tmp list */
#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("C "); DetectAddressDataPrint(tmp_c->ad); printf(" ");
for(sg = tmp_c->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
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
        printf("cut r == ADDRESS_EB\n");
#endif
        if (a_ip1 == b_ip1) {
#ifdef DBG
            printf("1\n");
#endif
            a->ad->ip[0]   = htonl(b_ip1);
            a->ad->ip2[0] = htonl(b_ip2);

            b->ad->ip[0]   = htonl(b_ip2 + 1);
            b->ad->ip2[0] = htonl(a_ip2);

            /* 'b' overlaps 'a' so a needs the 'b' sigs */
            SigGroupListCopyAppend(b,tmp);
            SigGroupListClean(b->sh);
            SigGroupListCopyAppend(a,b);
            SigGroupListCopyAppend(tmp,a);
            SigGroupListClean(tmp->sh);
#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
        } else if (a_ip2 == b_ip2) {
#ifdef DBG
            printf("2\n");
#endif
            a->ad->ip[0]   = htonl(a_ip1);
            a->ad->ip2[0] = htonl(b_ip1 - 1);

            b->ad->ip[0]   = htonl(b_ip1);
            b->ad->ip2[0] = htonl(b_ip2);

            /* 'a' overlaps 'b' so a needs the 'a' sigs */
            SigGroupListCopyPrepend(a,b);
#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
        } else {
#ifdef DBG
            printf("3\n");
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
            SigGroupListCopyPrepend(a,b);
            SigGroupListCopyAppend(a,tmp_c);
#ifdef DBG
SigGroupContainer *sg;
printf("A "); DetectAddressDataPrint(a->ad); printf(" ");
for(sg = a->sh ? a->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("B "); DetectAddressDataPrint(b->ad); printf(" ");
for(sg = b->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n");
printf("C "); DetectAddressDataPrint(tmp_c->ad); printf(" ");
for(sg = tmp_c->sh ? b->sh->head : NULL; sg != NULL; sg = sg->next) printf("%u ", sg->s->id); printf("\n\n");
#endif
        }
    }

    /* XXX free tmp */
    DetectAddressGroupFree(tmp);
    return 0;

error:
    /* XXX free tmp */
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


