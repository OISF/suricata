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
 * Implements the ssh.softwareversion keyword
 * You can match over the software version string of ssh, and it will
 * be compared from the beginning of the string so you can say for
 * example ssh.softwareversion:"PuTTY" and it can match, or you can
 * also specify the version, something like
 * ssh.softwareversion:"PuTTY-Release-0.55"
 * I find this useful to match over a known vulnerable server/client
 * software version incombination to other checks, so you can know
 * that the risk is higher
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
#include "detect-ssh-software-version.h"
#include "rust.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing the softwareversion string
 */
#define PARSE_REGEX  "^\\s*\"?\\s*?([0-9a-zA-Z\\:\\.\\-\\_\\+\\s+]+)\\s*\"?\\s*$"

static DetectParseRegex parse_regex;

static int DetectSshSoftwareVersionMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectSshSoftwareVersionSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectSshSoftwareVersionRegisterTests(void);
#endif
static void DetectSshSoftwareVersionFree(DetectEngineCtx *de_ctx, void *);
static int g_ssh_banner_list_id = 0;

static int InspectSshBanner(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

/**
 * \brief Registration function for keyword: ssh.softwareversion
 */
void DetectSshSoftwareVersionRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].name = "ssh.softwareversion";
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].desc = "match SSH software string";
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].url = "/rules/ssh-keywords.html#ssh-softwareversion";
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].AppLayerTxMatch = DetectSshSoftwareVersionMatch;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].Setup = DetectSshSoftwareVersionSetup;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].Free  = DetectSshSoftwareVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].RegisterTests = DetectSshSoftwareVersionRegisterTests;
#endif
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].flags = SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_INFO_DEPRECATED;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].alternative = DETECT_AL_SSH_SOFTWARE;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_ssh_banner_list_id = DetectBufferTypeRegister("ssh_banner");

    DetectAppLayerInspectEngineRegister2("ssh_banner", ALPROTO_SSH, SIG_FLAG_TOSERVER,
            SshStateBannerDone, InspectSshBanner, NULL);
    DetectAppLayerInspectEngineRegister2("ssh_banner", ALPROTO_SSH, SIG_FLAG_TOCLIENT,
            SshStateBannerDone, InspectSshBanner, NULL);
}

/**
 * \brief match the specified version on a ssh session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSshSoftwareVersionData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSshSoftwareVersionMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    DetectSshSoftwareVersionData *ssh = (DetectSshSoftwareVersionData *)m;
    if (state == NULL) {
        SCLogDebug("no ssh state, no match");
        SCReturnInt(0);
    }

    int ret = 0;
    const uint8_t *software = NULL;
    uint32_t b_len = 0;

    if (rs_ssh_tx_get_software(txv, &software, &b_len, flags) != 1)
        SCReturnInt(0);
    if (software == NULL || b_len == 0)
        SCReturnInt(0);
    if (b_len == ssh->len) {
        if (memcmp(software, ssh->software_ver, ssh->len) == 0) {
            ret = 1;
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
 * \retval id_d pointer to DetectSshSoftwareVersionData on success
 * \retval NULL on failure
 */
static DetectSshSoftwareVersionData *DetectSshSoftwareVersionParse (DetectEngineCtx *de_ctx, const char *str)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;

    ret = DetectParsePcreExec(&parse_regex, str, 0, 0);

    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid ssh.softwareversion option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr = NULL;
        res = pcre2_substring_get_bynumber(
                parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }

        /* We have a correct id option */
        ssh = SCMalloc(sizeof(DetectSshSoftwareVersionData));
        if (unlikely(ssh == NULL))
            goto error;

        ssh->software_ver = (uint8_t *)SCStrdup((char *)str_ptr);
        if (ssh->software_ver == NULL) {
            goto error;
        }
        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);

        ssh->len = (uint16_t)strlen((char *)ssh->software_ver);

        SCLogDebug("will look for ssh %s", ssh->software_ver);
    }

    return ssh;

error:
    if (ssh != NULL)
        DetectSshSoftwareVersionFree(de_ctx, ssh);
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
static int DetectSshSoftwareVersionSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) != 0)
        return -1;

    ssh = DetectSshSoftwareVersionParse(NULL, str);
    if (ssh == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_SSH_SOFTWAREVERSION;
    sm->ctx = (void *)ssh;

    SigMatchAppendSMToList(s, sm, g_ssh_banner_list_id);
    return 0;

error:
    if (ssh != NULL)
        DetectSshSoftwareVersionFree(de_ctx, ssh);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectSshSoftwareVersionData
 *
 * \param id_d pointer to DetectSshSoftwareVersionData
 */
static void DetectSshSoftwareVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        return;

    DetectSshSoftwareVersionData *ssh = (DetectSshSoftwareVersionData *)ptr;
    if (ssh->software_ver != NULL)
        SCFree(ssh->software_ver);
    SCFree(ssh);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectSshSoftwareVersionTestParse01 is a test to make sure that we parse
 *       a software version correctly
 */
static int DetectSshSoftwareVersionTestParse01 (void)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    ssh = DetectSshSoftwareVersionParse(NULL, "PuTTY_1.0");
    if (ssh != NULL && strncmp((char *) ssh->software_ver, "PuTTY_1.0", 9) == 0) {
        DetectSshSoftwareVersionFree(NULL, ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshSoftwareVersionTestParse02 is a test to make sure that we parse
 *       the software version correctly
 */
static int DetectSshSoftwareVersionTestParse02 (void)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    ssh = DetectSshSoftwareVersionParse(NULL, "\"SecureCRT-4.0\"");
    if (ssh != NULL && strncmp((char *) ssh->software_ver, "SecureCRT-4.0", 13) == 0) {
        DetectSshSoftwareVersionFree(NULL, ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshSoftwareVersionTestParse03 is a test to make sure that we
 *       don't return a ssh_data with an empty value specified
 */
static int DetectSshSoftwareVersionTestParse03 (void)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    ssh = DetectSshSoftwareVersionParse(NULL, "");
    if (ssh != NULL) {
        DetectSshSoftwareVersionFree(NULL, ssh);
        return 0;
    }

    return 1;
}


#include "stream-tcp-reassemble.h"
#include "stream-tcp-util.h"

/** \test Send a get request in three chunks + more data. */
static int DetectSshSoftwareVersionTestDetect01(void)
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

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.softwareversion:PuTTY_2.123; sid:1;)");
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
static int DetectSshSoftwareVersionTestDetect02(void)
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

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.softwareversion:PuTTY_2.123; sid:1;)");
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
static int DetectSshSoftwareVersionTestDetect03(void)
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

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.softwareversion:lalala-3.1.4; sid:1;)");
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
 * \brief this function registers unit tests for DetectSshSoftwareVersion
 */
static void DetectSshSoftwareVersionRegisterTests(void)
{
    UtRegisterTest("DetectSshSoftwareVersionTestParse01",
                   DetectSshSoftwareVersionTestParse01);
    UtRegisterTest("DetectSshSoftwareVersionTestParse02",
                   DetectSshSoftwareVersionTestParse02);
    UtRegisterTest("DetectSshSoftwareVersionTestParse03",
                   DetectSshSoftwareVersionTestParse03);
    UtRegisterTest("DetectSshSoftwareVersionTestDetect01",
                   DetectSshSoftwareVersionTestDetect01);
    UtRegisterTest("DetectSshSoftwareVersionTestDetect02",
                   DetectSshSoftwareVersionTestDetect02);
    UtRegisterTest("DetectSshSoftwareVersionTestDetect03",
                   DetectSshSoftwareVersionTestDetect03);
}
#endif /* UNITTESTS */
