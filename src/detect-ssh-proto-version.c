/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Implements the ssh.protoversion keyword
 * You can specify a concrete version like ssh.protoversion: 1.66
 * or search for protoversion 2 compat (1.99 is considered as 2) like
 * ssh.protoversion:2_compat
 * or just the beginning of the string like ssh.protoversion:"1."
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ssh.h"
#include "detect-ssh-proto-version.h"
#include "rust.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing the protoversion string
 */
#define PARSE_REGEX  "^\\s*\"?\\s*([0-9]+([\\.\\-0-9]+)?|2_compat)\\s*\"?\\s*$"

static DetectParseRegex parse_regex;

static int DetectSshVersionMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectSshVersionSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectSshVersionRegisterTests(void);
#endif
static void DetectSshVersionFree(DetectEngineCtx *, void *);
static int g_ssh_banner_list_id = 0;

/**
 * \brief Registration function for keyword: ssh.protoversion
 */
void DetectSshVersionRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].name = "ssh.protoversion";
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].desc = "match SSH protocol version";
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].url = "/rules/ssh-keywords.html#ssh-protoversion";
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].AppLayerTxMatch = DetectSshVersionMatch;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].Setup = DetectSshVersionSetup;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].Free  = DetectSshVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].RegisterTests = DetectSshVersionRegisterTests;
#endif
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].flags = SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_INFO_DEPRECATED;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].alternative = DETECT_AL_SSH_PROTOCOL;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_ssh_banner_list_id = DetectBufferTypeRegister("ssh_banner");
}

/**
 * \brief match the specified version on a ssh session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSshVersionData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSshVersionMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    SCLogDebug("lets see");

    DetectSshVersionData *ssh = (DetectSshVersionData *)m;
    if (state == NULL) {
        SCLogDebug("no ssh state, no match");
        SCReturnInt(0);
    }

    int ret = 0;
    const uint8_t *protocol = NULL;
    uint32_t b_len = 0;

    if (rs_ssh_tx_get_protocol(txv, &protocol, &b_len, flags) != 1)
        SCReturnInt(0);
    if (protocol == NULL || b_len == 0)
        SCReturnInt(0);

    if (ssh->flags & SSH_FLAG_PROTOVERSION_2_COMPAT) {
        SCLogDebug("looking for ssh protoversion 2 compat");
        if (protocol[0] == '2') {
            ret = 1;
        } else if (b_len >= 4) {
            if (memcmp(protocol, "1.99", 4) == 0)    {
                ret = 1;
            }
        }
    } else {
        SCLogDebug("looking for ssh protoversion %s length %"PRIu16"", ssh->ver, ssh->len);
        if (b_len == ssh->len) {
            if (memcmp(protocol, ssh->ver, ssh->len) == 0) {
                ret = 1;
            }
        }
    }
    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param de_ctx Pointer to the detection engine context
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectSshVersionData on success
 * \retval NULL on failure
 */
static DetectSshVersionData *DetectSshVersionParse (DetectEngineCtx *de_ctx, const char *str)
{
    DetectSshVersionData *ssh = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;

    ret = DetectParsePcreExec(&parse_regex, str, 0, 0);
    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid ssh.protoversion option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre2_substring_get_bynumber(
                parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }

        /* We have a correct id option */
        ssh = SCMalloc(sizeof(DetectSshVersionData));
        if (unlikely(ssh == NULL)) {
            pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
            goto error;
        }
        memset(ssh, 0x00, sizeof(DetectSshVersionData));

        /* If we expect a protocol version 2 or 1.99 (considered 2, we
         * will compare it with both strings) */
        if (strcmp("2_compat", str_ptr) == 0) {
            ssh->flags |= SSH_FLAG_PROTOVERSION_2_COMPAT;
            SCLogDebug("will look for ssh protocol version 2 (2, 2.0, 1.99 that's considered as 2");
            pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
            return ssh;
        }

        ssh->ver = (uint8_t *)SCStrdup((char*)str_ptr);
        if (ssh->ver == NULL) {
            pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
            goto error;
        }
        ssh->len = (uint16_t)strlen((char *)ssh->ver);
        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);

        SCLogDebug("will look for ssh %s", ssh->ver);
    }

    return ssh;

error:
    if (ssh != NULL)
        DetectSshVersionFree(de_ctx, ssh);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSshVersionSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectSshVersionData *ssh = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) != 0)
        return -1;

    ssh = DetectSshVersionParse(de_ctx, str);
    if (ssh == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_SSH_PROTOVERSION;
    sm->ctx = (void *)ssh;

    SigMatchAppendSMToList(s, sm, g_ssh_banner_list_id);
    return 0;

error:
    if (ssh != NULL)
        DetectSshVersionFree(de_ctx, ssh);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectSshVersionData
 *
 * \param id_d pointer to DetectSshVersionData
 */
void DetectSshVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectSshVersionData *sshd = (DetectSshVersionData *)ptr;
    SCFree(sshd->ver);
    SCFree(sshd);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectSshVersionTestParse01 is a test to make sure that we parse
 *       a proto version correctly
 */
static int DetectSshVersionTestParse01 (void)
{
    DetectSshVersionData *ssh = NULL;
    ssh = DetectSshVersionParse(NULL, "1.0");
    if (ssh != NULL && strncmp((char *) ssh->ver, "1.0", 3) == 0) {
        DetectSshVersionFree(NULL, ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshVersionTestParse02 is a test to make sure that we parse
 *       the proto version (compatible with proto version 2) correctly
 */
static int DetectSshVersionTestParse02 (void)
{
    DetectSshVersionData *ssh = NULL;
    ssh = DetectSshVersionParse(NULL, "2_compat");
    if (ssh->flags & SSH_FLAG_PROTOVERSION_2_COMPAT) {
        DetectSshVersionFree(NULL, ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshVersionTestParse03 is a test to make sure that we
 *       don't return a ssh_data with an invalid value specified
 */
static int DetectSshVersionTestParse03 (void)
{
    DetectSshVersionData *ssh = NULL;
    ssh = DetectSshVersionParse(NULL, "2_com");
    if (ssh != NULL) {
        DetectSshVersionFree(NULL, ssh);
        return 0;
    }
    ssh = DetectSshVersionParse(NULL, "");
    if (ssh != NULL) {
        DetectSshVersionFree(NULL, ssh);
        return 0;
    }
    ssh = DetectSshVersionParse(NULL, ".1");
    if (ssh != NULL) {
        DetectSshVersionFree(NULL, ssh);
        return 0;
    }
    ssh = DetectSshVersionParse(NULL, "lalala");
    if (ssh != NULL) {
        DetectSshVersionFree(NULL, ssh);
        return 0;
    }

    return 1;
}


#include "stream-tcp-reassemble.h"
#include "stream-tcp-util.h"

/** \test Send a get request in three chunks + more data. */
static int DetectSshVersionTestDetect01(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-1.";
    uint8_t sshbuf2[] = "10-PuTTY_2.123" ;
    uint8_t sshbuf3[] = "\n";
    uint8_t sshbuf4[] = "whatever...";

    uint8_t* sshbufs[4] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4};
    uint32_t sshlens[4] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3) - 1, sizeof(sshbuf4) - 1};

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.server, 1);
    StreamTcpUTSetupStream(&ssn.client, 1);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1234, 2222);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_SSH;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF(unlikely(p == NULL));
    p->flow = f;

    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.protoversion:1.10; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a get request in three chunks + more data. */
static int DetectSshVersionTestDetect02(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-1.99-Pu";
    uint8_t sshbuf2[] = "TTY_2.123" ;
    uint8_t sshbuf3[] = "\n";
    uint8_t sshbuf4[] = "whatever...";

    uint8_t* sshbufs[4] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4};
    uint32_t sshlens[4] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3) - 1, sizeof(sshbuf4) - 1};

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.server, 1);
    StreamTcpUTSetupStream(&ssn.client, 1);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1234, 2222);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_SSH;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF(unlikely(p == NULL));
    p->flow = f;

    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.protoversion:2_compat; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a get request in three chunks + more data. */
static int DetectSshVersionTestDetect03(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-1.";
    uint8_t sshbuf2[] = "7-PuTTY_2.123" ;
    uint8_t sshbuf3[] = "\n";
    uint8_t sshbuf4[] = "whatever...";

    uint8_t* sshbufs[4] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4};
    uint32_t sshlens[4] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3) - 1, sizeof(sshbuf4) - 1};

    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.server, 1);
    StreamTcpUTSetupStream(&ssn.client, 1);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1234, 2222);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_SSH;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF(unlikely(p == NULL));
    p->flow = f;

    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.protoversion:2_compat; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectSshVersion
 */
static void DetectSshVersionRegisterTests(void)
{
    UtRegisterTest("DetectSshVersionTestParse01", DetectSshVersionTestParse01);
    UtRegisterTest("DetectSshVersionTestParse02", DetectSshVersionTestParse02);
    UtRegisterTest("DetectSshVersionTestParse03", DetectSshVersionTestParse03);
    UtRegisterTest("DetectSshVersionTestDetect01",
                   DetectSshVersionTestDetect01);
    UtRegisterTest("DetectSshVersionTestDetect02",
                   DetectSshVersionTestDetect02);
    UtRegisterTest("DetectSshVersionTestDetect03",
                   DetectSshVersionTestDetect03);
}
#endif /* UNITTESTS */
