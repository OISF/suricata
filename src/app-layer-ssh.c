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
 * \author Victor Julien <victor@inliniac.net>
 *
 * App-layer parser for SSH protocol
 *
 */

#include "suricata-common.h"

#include "stream-tcp.h"

#include "app-layer-detect-proto.h"
#include "app-layer-ssh.h"
#include "rust.h"

#ifdef UNITTESTS
#include "util-memcmp.h"
#include "util-byte.h"
#include "flow-private.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "conf.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "util-pool.h"
#include "util-print.h"
#include "threads.h"
#include "decode.h"
#endif
/* HASSH fingerprints are disabled by default */
#define SSH_CONFIG_DEFAULT_HASSH false

static int SSHRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SSH,
                                               "SSH-", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SSH,
                                               "SSH-", 4, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    return 0;
}

int SSHTxLogCondition(ThreadVars * tv, const Packet * p, void *state, void *tx, uint64_t tx_id)
{
    return rs_ssh_tx_get_log_condition(tx);
}

/** \brief Function to register the SSH protocol parsers and other functions
 */
void RegisterSSHParsers(void)
{
    const char *proto_name = "ssh";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_SSH, proto_name);
        if (SSHRegisterPatternsForProtocolDetection() < 0)
            return;

        /* Check if we should generate Hassh fingerprints */
        int enable_hassh = SSH_CONFIG_DEFAULT_HASSH;
        const char *strval = NULL;
        if (ConfGet("app-layer.protocols.ssh.hassh", &strval) != 1) {
            enable_hassh = SSH_CONFIG_DEFAULT_HASSH;
        } else if (strcmp(strval, "auto") == 0) {
            enable_hassh = SSH_CONFIG_DEFAULT_HASSH;
        } else if (ConfValIsFalse(strval)) {
            enable_hassh = SSH_CONFIG_DEFAULT_HASSH;
        } else if (ConfValIsTrue(strval)) {
            enable_hassh = true;
        }

        if (RunmodeIsUnittests() || enable_hassh) {
            rs_ssh_enable_hassh();
        }
    }

    SCLogDebug("Registering Rust SSH parser.");
    rs_ssh_register_parser();


#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SSH, SSHParserRegisterTests);
#endif
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "flow-util.h"
#include "stream-tcp-util.h"
#include "util-unittest-helper.h"

static int SSHParserTestUtilCheck(const char *protoexp, const char *softexp, void *tx, uint8_t flags) {
    const uint8_t *protocol = NULL;
    uint32_t p_len = 0;
    const uint8_t *software = NULL;
    uint32_t s_len = 0;

    if (rs_ssh_tx_get_protocol(tx, &protocol, &p_len, flags) != 1) {
        printf("Version string not parsed correctly return: ");
        return 1;
    }
    if (protocol == NULL) {
        printf("Version string not parsed correctly NULL: ");
        return 1;
    }

    if (p_len != strlen(protoexp)) {
        printf("Version string not parsed correctly length: ");
        return 1;
    }
    if (memcmp(protocol, protoexp, strlen(protoexp)) != 0) {
        printf("Version string not parsed correctly: ");
        return 1;
    }

    if (softexp != NULL) {
        if (rs_ssh_tx_get_software(tx, &software, &s_len, flags) != 1)
            return 1;
        if (software == NULL)
            return 1;
        if (s_len != strlen(softexp)) {
            printf("Software string not parsed correctly length: ");
            return 1;
        }
        if (memcmp(software, softexp, strlen(softexp)) != 0) {
            printf("Software string not parsed correctly: ");
            return 1;
        }
    }
    return 0;
}

/** \test Send a version string in one chunk (client version str). */
static int SSHParserTest01(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-MySSHClient-0.5.1\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER | STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    if ( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOSERVER) != SshStateBannerDone ) {
        printf("Client version string not parsed: ");
        goto end;
    }

    if (SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER))
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a version string in one chunk but multiple lines and comments.
 *        (client version str)
 */
static int SSHParserTest02(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-MySSHClient-0.5.1 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER | STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);

    if ( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOSERVER) != SshStateBannerDone ) {
        printf("Client version string not parsed: ");
        goto end;
    }
    if (SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER))
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a invalid version string in one chunk but multiple lines and comments.
 *        (client version str)
 */
static int SSHParserTest03(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER | STREAM_EOF, sshbuf, sshlen);
    if (r == 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected != 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);

    if ( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOSERVER) == SshStateBannerDone ) {
        printf("Client version string parsed? It's not a valid string: ");
        goto end;
    }
    const uint8_t *dummy = NULL;
    uint32_t dummy_len = 0;
    if (rs_ssh_tx_get_protocol(tx, &dummy, &dummy_len, STREAM_TOSERVER) != 0)
        goto end;
    if (rs_ssh_tx_get_software(tx, &dummy, &dummy_len, STREAM_TOSERVER) != 0)
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a version string in one chunk (server version str). */
static int SSHParserTest04(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-MySSHClient-0.5.1\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOCLIENT | STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);

    if ( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOCLIENT) != SshStateBannerDone ) {
        printf("Client version string not parsed: ");
        goto end;
    }
    if (SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOCLIENT))
        goto end;

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a version string in one chunk (server version str)
 */
static int SSHParserTest05(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-MySSHClient-0.5.1 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOCLIENT | STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);

    if ( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOCLIENT) != SshStateBannerDone ) {
        printf("Client version string not parsed: ");
        goto end;
    }
    if (SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOCLIENT))
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a invalid version string in one chunk (server version str)
 */
static int SSHParserTest06(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0 some comments...\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOCLIENT | STREAM_EOF, sshbuf, sshlen);
    if (r == 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected != 0: ", r);
        goto end;
    }
    /* Ok, it returned an error. Let's make sure we didn't parse the string at all */

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);

    if ( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOCLIENT) == SshStateBannerDone ) {
        printf("Client version string parsed? It's not a valid string: ");
        goto end;
    }
    const uint8_t *dummy = NULL;
    uint32_t dummy_len = 0;
    if (rs_ssh_tx_get_protocol(tx, &dummy, &dummy_len, STREAM_TOCLIENT) != 0)
        goto end;
    if (rs_ssh_tx_get_software(tx, &dummy, &dummy_len, STREAM_TOCLIENT) != 0)
        goto end;


    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

#define MAX_SSH_TEST_SIZE 512

static int SSHParserTest07(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    char sshbufs[2][MAX_SSH_TEST_SIZE] = {"SSH-2.", "0-MySSHClient-0.5.1\r\n"};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<2; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client, seq, (uint8_t *) sshbufs[i], strlen(sshbufs[i])) == -1);
        seq += strlen(sshbufs[i]);
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOSERVER) != SshStateBannerDone );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a version banner in three chunks. */
static int SSHParserTest08(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    char sshbufs[3][MAX_SSH_TEST_SIZE] = {"SSH-", "2.", "0-MySSHClient-0.5.1\r\n"};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<3; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client, seq, (uint8_t *) sshbufs[i], strlen(sshbufs[i])) == -1);
        seq += strlen(sshbufs[i]);
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOSERVER) != SshStateBannerDone );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

static int SSHParserTest09(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    char sshbufs[2][MAX_SSH_TEST_SIZE] = {"SSH-2.", "0-MySSHClient-0.5.1\r\n"};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<2; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, (uint8_t *) sshbufs[i], strlen(sshbufs[i])) == -1);
        seq += strlen(sshbufs[i]);
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOCLIENT) != SshStateBannerDone );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a version banner in three chunks. */
static int SSHParserTest10(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    char sshbufs[3][MAX_SSH_TEST_SIZE] = {"SSH-", "2.", "0-MySSHClient-0.5.1\r\n"};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<3; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, (uint8_t *) sshbufs[i], strlen(sshbufs[i])) == -1);
        seq += strlen(sshbufs[i]);
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_alstate_progress(tx, STREAM_TOCLIENT) != SshStateBannerDone );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a banner and record in three chunks. */
static int SSHParserTest11(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-2.0-MySSHClient-0.5.1\r\n";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = { 0x00, 0x00, 0x00, 0x03, 0x01, 21, 0x00};
    uint32_t sshlen2 = sizeof(sshbuf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER,
                            sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    if ( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) != SshStateFinished ) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }
    if (SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER))
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a banner and 2 records record in four chunks. */
static int SSHParserTest12(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-2.0-MySSHClient-0.5.1\r\n";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = { 0x00, 0x00, 0x00, 0x03,0x01, 17, 0x00};
    uint32_t sshlen2 = sizeof(sshbuf2);
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03,0x01, 21, 0x00};
    uint32_t sshlen3 = sizeof(sshbuf3);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER,
                            sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER,
                            sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    if ( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) != SshStateFinished ) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }
    if (SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER))
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a banner and 2 records record in four chunks. */
static int SSHParserTest13(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-2.0-MySSHClient-0.5.1\r\n";
    uint8_t sshbuf2[] = { 0x00, 0x00, 0x00, 0x02, 0x01, 17};
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x02, 0x01, 21};

    uint8_t* sshbufs[3] = {sshbuf1, sshbuf2, sshbuf3};
    uint32_t sshlens[3] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2), sizeof(sshbuf3)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<3; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a banner and 2 records record in four chunks. */
static int SSHParserTest14(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-2.0-MySSHClient-0.5.1\r\n";
    uint8_t sshbuf2[] = { 0x00, 0x00, 0x00, 0x10, 0x01, 17, 0x00};
    uint8_t sshbuf3[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t sshbuf4[] = { 0x09, 0x10, 0x11, 0x12, 0x13, 0x00};
    /* first byte of this record in sshbuf4 */
    uint8_t sshbuf5[] = { 0x00, 0x00, 0x02, 0x01, 21};

    uint8_t* sshbufs[5] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4, sshbuf5};
    uint32_t sshlens[5] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2), sizeof(sshbuf3), sizeof(sshbuf4), sizeof(sshbuf5)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<5; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send a banner and 2 records record in four chunks. */
static int SSHParserTest15(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-2.0-MySSHClient-0.5.1\r\n";
    uint8_t sshbuf2[] = { 0x00, 0x00, 0x00, 0x10, 0x01, 17, 0x00};
    uint8_t sshbuf3[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t sshbuf4[] = { 0x09, 0x10, 0x11, 0x12, 0x13, 0x00};
    uint8_t sshbuf5[] = { 0x00, 0x00, 0x02, 0x01, 20, 0x00, 0x00, 0x00, 0x02, 0x01, 21};

    uint8_t* sshbufs[5] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4, sshbuf5};
    uint32_t sshlens[5] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2), sizeof(sshbuf3), sizeof(sshbuf4), sizeof(sshbuf5)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<5; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.client, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOSERVER));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send toserver a banner and record in three chunks. */
static int SSHParserTest16(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03,0x01, 21, 0x00};

    uint8_t* sshbufs[3] = {sshbuf1, sshbuf2, sshbuf3};
    uint32_t sshlens[3] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<3; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Send toserver a banner and 2 records record in four chunks. */
static int SSHParserTest17(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03, 0x01, 17, 0x00};
    uint8_t sshbuf4[] = { 0x00, 0x00, 0x00, 0x03, 0x01, 21, 0x00};

    uint8_t* sshbufs[4] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4};
    uint32_t sshlens[4] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3), sizeof(sshbuf4)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", "MySSHClient-0.5.1", tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test 2 directional test */
static int SSHParserTest18(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t server1[] = "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu3\r\n";
    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-MySSHClient-0.5.1\r\n";
    uint8_t server2[] = { 0x00, 0x00, 0x00, 0x03, 0x01, 21, 0x00 };
    uint8_t sshbuf3[] = { 0x00, 0x00, 0x00, 0x03, 0x01, 21, 0x00 };


    memset(&tv, 0x00, sizeof(tv));

    StreamTcpUTInit(&ra_ctx);
    StreamTcpUTInitInline();
    StreamTcpUTSetupSession(&ssn);
    StreamTcpUTSetupStream(&ssn.server, 1);
    StreamTcpUTSetupStream(&ssn.client, 1);

    uint8_t* sshbufs[5] = {server1, sshbuf1, sshbuf2, server2, sshbuf3};
    uint32_t sshlens[5] = {sizeof(server1) - 1, sizeof(sshbuf1) - 1, sizeof(sshbuf2) -1, sizeof(server2) - 1, sizeof(sshbuf3)};
    bool sshdirs[5] = {true, false, false, true, false};

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1234, 2222);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_SSH;

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seqcli = 2;
    uint32_t seqsrv = 2;
    for (int i=0; i<5; i++) {
        if (sshdirs[i]) {
            FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seqsrv, sshbufs[i], sshlens[i]) == -1);
            seqsrv += sshlens[i];
            FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn,  &ssn.server, p, UPDATE_DIR_PACKET) < 0);
        } else {
            FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx,  &ssn.client, seqcli, sshbufs[i], sshlens[i]) == -1);
            seqcli += sshlens[i];
            FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.client, p, UPDATE_DIR_PACKET) < 0);
        }
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

    FAIL_IF(!(AppLayerParserStateIssetFlag(f->alparser, APP_LAYER_PARSER_NO_INSPECTION)));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Really long banner handling: bannel exactly 255 */
static int SSHParserTest19(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-";
    uint8_t sshbuf3[] = "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//60
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//112
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//164
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//216
                        "abcdefghijklmnopqrstuvwxyz"//242
                        "abcdefghijkl\r";//255
    uint8_t sshbuf4[] = { 0x00, 0x00, 0x00, 0x03, 0x01, 21, 0x00};

    uint8_t* sshbufs[4] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4};
    uint32_t sshlens[4] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3) - 1, sizeof(sshbuf4)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

    sshbuf3[sizeof(sshbuf3) - 2] = 0;
    FAIL_IF(SSHParserTestUtilCheck("2.0", (char *)sshbuf3, tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Really long banner handling: banner exactly 255,
 *        followed by malformed record */
static int SSHParserTest20(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-";
    uint8_t sshbuf3[] = "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//60
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//112
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//164
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//216
                        "abcdefghijklmnopqrstuvwxyz"//242
                        "abcdefghijklm\r";//256
    uint8_t sshbuf4[] = {'a','b','c','d','e','f', '\r',
                         0x00, 0x00, 0x00, 0x06, 0x01, 21, 0x00, 0x00, 0x00};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", NULL, tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Fragmented banner handling: chunk has final part of bannel plus
 *        a record. */
static int SSHParserTest21(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-";
    uint8_t sshbuf3[] = "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//60
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//112
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//164
                        "abcdefghijklmnopqrstuvwxyz"
                        "abcdefghijklmnopqrstuvwxyz"//216
                        "abcdefghijklmnopqrstuvwxy";//241
    uint8_t sshbuf4[] = {'l','i','b','s','s','h', '\r',
                         0x00, 0x00, 0x00, 0x06, 0x01, 21, 0x00, 0x00, 0x00};

    uint8_t* sshbufs[4] = {sshbuf1, sshbuf2, sshbuf3, sshbuf4};
    uint32_t sshlens[4] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3) - 1, sizeof(sshbuf4)};

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

    p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    p->proto = IPPROTO_TCP;
    p->flow = f;

    uint32_t seq = 2;
    for (int i=0; i<4; i++) {
        FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
        seq += sshlens[i];
        FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
    }

    void *ssh_state = f->alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

    FAIL_IF(SSHParserTestUtilCheck("2.0", NULL, tx, STREAM_TOCLIENT));

    UTHFreePacket(p);
    StreamTcpUTClearSession(&ssn);
    StreamTcpUTDeinit(ra_ctx);
    UTHFreeFlow(f);
    PASS;
}

/** \test Fragmented banner handling: chunk has final part of bannel plus
 *        a record. */
static int SSHParserTest22(void)
{
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    ThreadVars tv;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;

    uint8_t sshbuf1[] = "SSH-";
    uint8_t sshbuf2[] = "2.0-";
    uint8_t sshbuf3[] = {
        'l', 'i', 'b', 's', 's', 'h', '\r', //7

        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00, //50

        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00, //100

        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00, //150

        0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00, //200

            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00, //250

            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 17, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x06, 0x01, 21, 0x00, 0x00, 0x00, 0x00, //300
        };


        uint8_t* sshbufs[3] = {sshbuf1, sshbuf2, sshbuf3};
        uint32_t sshlens[3] = {sizeof(sshbuf1) - 1, sizeof(sshbuf2) - 1, sizeof(sshbuf3) - 1};

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

        p = PacketGetFromAlloc();
        FAIL_IF(unlikely(p == NULL));
        p->proto = IPPROTO_TCP;
        p->flow = f;

        uint32_t seq = 2;
        for (int i=0; i<3; i++) {
            FAIL_IF(StreamTcpUTAddSegmentWithPayload(&tv, ra_ctx, &ssn.server, seq, sshbufs[i], sshlens[i]) == -1);
            seq += sshlens[i];
            FAIL_IF(StreamTcpReassembleAppLayer(&tv, ra_ctx, &ssn, &ssn.server, p, UPDATE_DIR_PACKET) < 0);
        }

        void *ssh_state = f->alstate;
        FAIL_IF_NULL(ssh_state);
        void * tx = rs_ssh_state_get_tx(ssh_state, 0);
        FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOCLIENT) != SshStateFinished );

        FAIL_IF(SSHParserTestUtilCheck("2.0", "libssh", tx, STREAM_TOCLIENT));

        UTHFreePacket(p);
        StreamTcpUTClearSession(&ssn);
        StreamTcpUTDeinit(ra_ctx);
        UTHFreeFlow(f);
        PASS;
}

/** \test Send a version string in one chunk (client version str). */
static int SSHParserTest23(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0\r-MySSHClient-0.5.1\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER | STREAM_EOF, sshbuf, sshlen);
    if (r == 0) {
        printf("toclient chunk 1 returned 0 expected non null: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a version string in one chunk (client version str). */
static int SSHParserTest24(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf[] = "SSH-2.0-\rMySSHClient-0.5.1\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER | STREAM_EOF, sshbuf, sshlen);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    void *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    if ( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) != SshStateBannerDone ) {
        printf("Didn't detect the msg code of new keys (ciphered data starts): ");
        goto end;
    }
    if (SSHParserTestUtilCheck("2.0", NULL, tx, STREAM_TOSERVER))
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a malformed banner */
static int SSHParserTest25(void)
{
    Flow f;
    uint8_t sshbuf[] = "\n";
    uint32_t sshlen = sizeof(sshbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SSH,
                                STREAM_TOSERVER | STREAM_EOF, sshbuf, sshlen);
    FAIL_IF(r != -1);

    void *ssh_state = f.alstate;
    FAIL_IF_NULL(ssh_state);
    void * tx = rs_ssh_state_get_tx(ssh_state, 0);
    FAIL_IF( rs_ssh_tx_get_flags(tx, STREAM_TOSERVER) == SshStateBannerDone );
    const uint8_t *dummy = NULL;
    uint32_t dummy_len = 0;
    FAIL_IF (rs_ssh_tx_get_software(tx, &dummy, &dummy_len, STREAM_TOCLIENT) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

#endif /* UNITTESTS */

void SSHParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SSHParserTest01 - ToServer", SSHParserTest01);
    UtRegisterTest("SSHParserTest02 - ToServer", SSHParserTest02);
    UtRegisterTest("SSHParserTest03 - ToServer", SSHParserTest03);
    UtRegisterTest("SSHParserTest04 - ToClient", SSHParserTest04);
    UtRegisterTest("SSHParserTest05 - ToClient", SSHParserTest05);
    UtRegisterTest("SSHParserTest06 - ToClient", SSHParserTest06);
    UtRegisterTest("SSHParserTest07 - ToServer 2 chunks", SSHParserTest07);
    UtRegisterTest("SSHParserTest08 - ToServer 3 chunks", SSHParserTest08);
    UtRegisterTest("SSHParserTest09 - ToClient 2 chunks", SSHParserTest09);
    UtRegisterTest("SSHParserTest10 - ToClient 3 chunks", SSHParserTest10);
    UtRegisterTest("SSHParserTest11 - ToClient 4 chunks", SSHParserTest11);
    UtRegisterTest("SSHParserTest12 - ToClient 4 chunks", SSHParserTest12);
    UtRegisterTest("SSHParserTest13 - ToClient 4 chunks", SSHParserTest13);
    UtRegisterTest("SSHParserTest14 - ToClient 4 chunks", SSHParserTest14);
    UtRegisterTest("SSHParserTest15", SSHParserTest15);
    UtRegisterTest("SSHParserTest16", SSHParserTest16);
    UtRegisterTest("SSHParserTest17", SSHParserTest17);
    UtRegisterTest("SSHParserTest18", SSHParserTest18);
    UtRegisterTest("SSHParserTest19", SSHParserTest19);
    UtRegisterTest("SSHParserTest20", SSHParserTest20);
    UtRegisterTest("SSHParserTest21", SSHParserTest21);
    UtRegisterTest("SSHParserTest22", SSHParserTest22);
    UtRegisterTest("SSHParserTest23", SSHParserTest23);
    UtRegisterTest("SSHParserTest24", SSHParserTest24);
    UtRegisterTest("SSHParserTest25", SSHParserTest25);
#endif /* UNITTESTS */
}

