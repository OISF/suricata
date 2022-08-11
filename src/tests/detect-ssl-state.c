/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 */

static int DetectSslStateTest01(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("client_hello");
    FAIL_IF_NULL(ssd);
    FAIL_IF_NOT(ssd->flags == DETECT_SSL_STATE_CLIENT_HELLO);
    SCFree(ssd);
    PASS;
}

static int DetectSslStateTest02(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("server_hello , client_hello");
    FAIL_IF_NULL(ssd);
    FAIL_IF_NOT(ssd->flags == (DETECT_SSL_STATE_SERVER_HELLO |
            DETECT_SSL_STATE_CLIENT_HELLO));
    SCFree(ssd);
    PASS;
}

static int DetectSslStateTest03(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("server_hello , client_keyx , "
                                                  "client_hello");
    FAIL_IF_NULL(ssd);
    FAIL_IF_NOT(ssd->flags == (DETECT_SSL_STATE_SERVER_HELLO |
                       DETECT_SSL_STATE_CLIENT_KEYX |
                       DETECT_SSL_STATE_CLIENT_HELLO));
    SCFree(ssd);
    PASS;
}

static int DetectSslStateTest04(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("server_hello , client_keyx , "
                                                  "client_hello , server_keyx , "
                                                  "unknown");
    FAIL_IF_NULL(ssd);
    FAIL_IF_NOT(ssd->flags == (DETECT_SSL_STATE_SERVER_HELLO |
                       DETECT_SSL_STATE_CLIENT_KEYX |
                       DETECT_SSL_STATE_CLIENT_HELLO |
                       DETECT_SSL_STATE_SERVER_KEYX |
                       DETECT_SSL_STATE_UNKNOWN));
    SCFree(ssd);
    PASS;
}

static int DetectSslStateTest05(void)
{
    DetectSslStateData *ssd = DetectSslStateParse(", server_hello , client_keyx , "
                                                  "client_hello , server_keyx , "
                                                  "unknown");

    FAIL_IF_NOT_NULL(ssd);
    PASS;
}

static int DetectSslStateTest06(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("server_hello , client_keyx , "
                                                  "client_hello , server_keyx , "
                                                  "unknown , ");
    FAIL_IF_NOT_NULL(ssd);
    PASS;
}

/**
 * \brief Test that the "|" character still works as a separate for
 * compatibility with older Suricata rules.
 */
static int DetectSslStateTest08(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("server_hello|client_hello");
    FAIL_IF_NULL(ssd);
    FAIL_IF_NOT(ssd->flags == (DETECT_SSL_STATE_SERVER_HELLO |
            DETECT_SSL_STATE_CLIENT_HELLO));
    SCFree(ssd);
    PASS;
}

/**
 * \test Test parsing of negated states.
 */
static int DetectSslStateTestParseNegate(void)
{
    DetectSslStateData *ssd = DetectSslStateParse("!client_hello");
    FAIL_IF_NULL(ssd);
    uint32_t expected = DETECT_SSL_STATE_CLIENT_HELLO;
    FAIL_IF(ssd->flags != expected || ssd->mask != expected);
    SCFree(ssd);

    ssd = DetectSslStateParse("!client_hello,!server_hello");
    FAIL_IF_NULL(ssd);
    expected = DETECT_SSL_STATE_CLIENT_HELLO | DETECT_SSL_STATE_SERVER_HELLO;
    FAIL_IF(ssd->flags != expected || ssd->mask != expected);
    SCFree(ssd);

    PASS;
}

static void DetectSslStateRegisterTests(void)
{
    UtRegisterTest("DetectSslStateTest01", DetectSslStateTest01);
    UtRegisterTest("DetectSslStateTest02", DetectSslStateTest02);
    UtRegisterTest("DetectSslStateTest03", DetectSslStateTest03);
    UtRegisterTest("DetectSslStateTest04", DetectSslStateTest04);
    UtRegisterTest("DetectSslStateTest05", DetectSslStateTest05);
    UtRegisterTest("DetectSslStateTest06", DetectSslStateTest06);
    UtRegisterTest("DetectSslStateTest08", DetectSslStateTest08);
    UtRegisterTest("DetectSslStateTestParseNegate",
        DetectSslStateTestParseNegate);
}
