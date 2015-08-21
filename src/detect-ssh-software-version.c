/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#include "stream-tcp.h"

/**
 * \brief Regex for parsing the softwareversion string
 */
#define PARSE_REGEX  "^\\s*\"?\\s*?([0-9a-zA-Z\\:\\.\\-\\_\\+\\s+]+)\\s*\"?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectSshSoftwareVersionMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectSshSoftwareVersionSetup (DetectEngineCtx *, Signature *, char *);
void DetectSshSoftwareVersionRegisterTests(void);
void DetectSshSoftwareVersionFree(void *);
void DetectSshSoftwareVersionRegister(void);

/**
 * \brief Registration function for keyword: ssh.softwareversion
 */
void DetectSshSoftwareVersionRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].name = "ssh.softwareversion";
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].Match = NULL;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].AppLayerMatch = DetectSshSoftwareVersionMatch;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].alproto = ALPROTO_SSH;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].Setup = DetectSshSoftwareVersionSetup;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].Free  = DetectSshSoftwareVersionFree;
    sigmatch_table[DETECT_AL_SSH_SOFTWAREVERSION].RegisterTests = DetectSshSoftwareVersionRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

	SCLogDebug("registering ssh.softwareversion rule option");

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                    PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;
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
int DetectSshSoftwareVersionMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectSshSoftwareVersionData *ssh = (DetectSshSoftwareVersionData *)m->ctx;
    SshState *ssh_state = (SshState *)state;
    if (ssh_state == NULL) {
        SCLogDebug("no ssh state, no match");
        SCReturnInt(0);
    }

    int ret = 0;
    if ((flags & STREAM_TOCLIENT) && (ssh_state->srv_hdr.flags & SSH_FLAG_VERSION_PARSED)) {
        SCLogDebug("looking for ssh server softwareversion %s length %"PRIu16" on %s", ssh->software_ver, ssh->len, ssh_state->srv_hdr.software_version);
        ret = (strncmp((char *) ssh_state->srv_hdr.software_version, (char *) ssh->software_ver, ssh->len) == 0)? 1 : 0;
    } else if ((flags & STREAM_TOSERVER) && (ssh_state->cli_hdr.flags & SSH_FLAG_VERSION_PARSED)) {
        SCLogDebug("looking for ssh client softwareversion %s length %"PRIu16" on %s", ssh->software_ver, ssh->len, ssh_state->cli_hdr.software_version);
        ret = (strncmp((char *) ssh_state->cli_hdr.software_version, (char *) ssh->software_ver, ssh->len) == 0)? 1 : 0;
    }
    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectSshSoftwareVersionData on success
 * \retval NULL on failure
 */
DetectSshSoftwareVersionData *DetectSshSoftwareVersionParse (char *str)
{
    DetectSshSoftwareVersionData *ssh = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid ssh.softwareversion option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr = NULL;
        res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
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
        pcre_free_substring(str_ptr);

        ssh->len = strlen((char *)ssh->software_ver);

        SCLogDebug("will look for ssh %s", ssh->software_ver);
    }

    return ssh;

error:
    if (ssh != NULL)
        DetectSshSoftwareVersionFree(ssh);
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
static int DetectSshSoftwareVersionSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    SigMatch *sm = NULL;

    ssh = DetectSshSoftwareVersionParse(str);
    if (ssh == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_SSH) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_SSH_SOFTWAREVERSION;
    sm->ctx = (void *)ssh;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_SSH;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (ssh != NULL)
        DetectSshSoftwareVersionFree(ssh);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectSshSoftwareVersionData
 *
 * \param id_d pointer to DetectSshSoftwareVersionData
 */
void DetectSshSoftwareVersionFree(void *ptr)
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
int DetectSshSoftwareVersionTestParse01 (void)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    ssh = DetectSshSoftwareVersionParse("PuTTY_1.0");
    if (ssh != NULL && strncmp((char *) ssh->software_ver, "PuTTY_1.0", 9) == 0) {
        DetectSshSoftwareVersionFree(ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshSoftwareVersionTestParse02 is a test to make sure that we parse
 *       the software version correctly
 */
int DetectSshSoftwareVersionTestParse02 (void)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    ssh = DetectSshSoftwareVersionParse("\"SecureCRT-4.0\"");
    if (ssh != NULL && strncmp((char *) ssh->software_ver, "SecureCRT-4.0", 13) == 0) {
        DetectSshSoftwareVersionFree(ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshSoftwareVersionTestParse03 is a test to make sure that we
 *       don't return a ssh_data with an empty value specified
 */
int DetectSshSoftwareVersionTestParse03 (void)
{
    DetectSshSoftwareVersionData *ssh = NULL;
    ssh = DetectSshSoftwareVersionParse("");
    if (ssh != NULL) {
        DetectSshSoftwareVersionFree(ssh);
        return 0;
    }

    return 1;
}


#include "stream-tcp-reassemble.h"

/** \test Send a get request in three chunks + more data. */
static int DetectSshSoftwareVersionTestDetect01(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-1.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "10-PuTTY_2.123" ;
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = "\n";
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    uint8_t sshbuf4[] = "whatever...";
    uint32_t sshlen4 = sizeof(sshbuf4) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.softwareversion:PuTTY_2.123; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ( !(PacketAlertCheck(p, 1))) {
        printf("Error, the sig should match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    return result;
}

/** \test Send a get request in three chunks + more data. */
static int DetectSshSoftwareVersionTestDetect02(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-1.99-Pu";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "TTY_2.123" ;
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = "\n";
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    uint8_t sshbuf4[] = "whatever...";
    uint32_t sshlen4 = sizeof(sshbuf4) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.softwareversion:PuTTY_2.123; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ( !(PacketAlertCheck(p, 1))) {
        printf("Error, the sig should match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    return result;
}

/** \test Send a get request in three chunks + more data. */
static int DetectSshSoftwareVersionTestDetect03(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-1.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "7-PuTTY_2.123" ;
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = "\n";
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    uint8_t sshbuf4[] = "whatever...";
    uint32_t sshlen4 = sizeof(sshbuf4) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.softwareversion:lalala-3.1.4; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("Error, 1.7 version is not 2 compat, so the sig should not match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectSshSoftwareVersion
 */
void DetectSshSoftwareVersionRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectSshSoftwareVersionTestParse01", DetectSshSoftwareVersionTestParse01, 1);
    UtRegisterTest("DetectSshSoftwareVersionTestParse02", DetectSshSoftwareVersionTestParse02, 1);
    UtRegisterTest("DetectSshSoftwareVersionTestParse03", DetectSshSoftwareVersionTestParse03, 1);
    UtRegisterTest("DetectSshSoftwareVersionTestDetect01", DetectSshSoftwareVersionTestDetect01, 1);
    UtRegisterTest("DetectSshSoftwareVersionTestDetect02", DetectSshSoftwareVersionTestDetect02, 1);
    UtRegisterTest("DetectSshSoftwareVersionTestDetect03", DetectSshSoftwareVersionTestDetect03, 1);
#endif /* UNITTESTS */
}

