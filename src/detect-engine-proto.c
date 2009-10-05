/* Proto part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * TODO move this out of the detection plugin structure */

#include "eidps-common.h"

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-byte.h"
#include "util-unittest.h"

#include "detect-engine-siggroup.h"

int DetectProtoSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *sidstr);
void DetectProtoTests (void);

void DetectProtoRegister (void) {
    sigmatch_table[DETECT_PROTO].name = "__proto__";
    sigmatch_table[DETECT_PROTO].Match = NULL;
    sigmatch_table[DETECT_PROTO].Setup = DetectProtoSetup;
    sigmatch_table[DETECT_PROTO].Free = NULL;
    sigmatch_table[DETECT_PROTO].RegisterTests = DetectProtoTests;
}

DetectProto *DetectProtoInit(void) {
    DetectProto *dp = malloc(sizeof(DetectProto));
    if (dp == NULL) {
        return NULL;
    }
    memset(dp,0,sizeof(DetectProto));

    return dp;
}

/**
 * \brief Free a DetectAddressGroup object
 *
 * \param dp Pointer to the DetectProto instance to be freed
 */
void DetectProtoFree(DetectProto *dp) {
    if (dp == NULL)
        return;

    free(dp);
}

/**
 * \brief Parses a protocol sent as a string.
 *
 * \param dp  Pointer to the DetectProto instance which will be updated with the
 *            incoming protocol information.
 * \param str Pointer to the string containing the protocol name.
 *
 * \retval 0 Always return 0.
 */
int DetectProtoParse(DetectProto *dp, char *str) {
    int proto;

    if (strcasecmp(str, "tcp") == 0) {
        proto = IPPROTO_TCP;
        dp->proto[proto / 8] |= 1 << (proto % 8);
    } else if (strcasecmp(str, "udp") == 0) {
        proto = IPPROTO_UDP;
        dp->proto[proto / 8] |= 1 << (proto % 8);
    } else if (strcasecmp(str, "icmp") == 0) {
        proto = IPPROTO_ICMP;
        dp->proto[proto / 8] |= 1 << (proto % 8);
    } else if (strcasecmp(str,"ip") == 0) {
        /* Proto "ip" is treated as an "any" */
        dp->flags |= DETECT_PROTO_ANY;
    } else {
        uint8_t proto_u8; /* Used to avoid sign extension */

        /* Extract out a 0-256 value with validation checks */
        if (ByteExtractStringUint8(&proto_u8, 10, 0, str) == -1) {
            // XXX
            goto error;
        }
        proto = (int)proto_u8;

        /* Proto 0 is the same as "ip" above */
        if (proto == IPPROTO_IP) {
            dp->flags |= DETECT_PROTO_ANY;
        } else {
            dp->proto[proto / 8] |= 1<<(proto % 8);
        }
    }

    return 0;

error:
    return -1;
}

/* XXX remove */
int DetectProtoSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *str)
{
    return 0;
}

/* TESTS */

#ifdef UNITTESTS
static int ProtoTestParse01 (void) {
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "6");
    if (r == 0) {
        return 1;
    }

    return 0;
}

static int ProtoTestParse02 (void) {
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "tcp");
    if (r == 0 && dp.proto[(IPPROTO_TCP/8)] & (1<<(IPPROTO_TCP%8))) {
        return 1;
    }

    return 0;
}

static int ProtoTestParse03 (void) {
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "ip");
    if (r == 0 && dp.flags & DETECT_PROTO_ANY) {
        return 1;
    }

    return 0;
}

static int ProtoTestParse04 (void) {
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad number */
    int r = DetectProtoParse(&dp, "4242");
    if (r == -1) {
        return 1;
    }

    return 0;
}
#endif /* UNITTESTS */


void DetectProtoTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("ProtoTestParse01", ProtoTestParse01, 1);
    UtRegisterTest("ProtoTestParse02", ProtoTestParse02, 1);
    UtRegisterTest("ProtoTestParse03", ProtoTestParse03, 1);
    UtRegisterTest("ProtoTestParse04", ProtoTestParse04, 1);
#endif /* UNITTESTS */
}

