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
 * \file   detect-ssl-version.c
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#include "detect-engine-build.h"

/**
 * \test DetectSslVersionTestParse01 is a test to make sure that we parse the
 *      "ssl_version" option correctly when given valid ssl_version option
 */
static int DetectSslVersionTestParse01(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse(NULL, "SSlv3");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[SSLv3].ver == SSL_VERSION_3);
    DetectSslVersionFree(NULL, ssl);
    PASS;
}

/**
 * \test DetectSslVersionTestParse02 is a test to make sure that we parse the
 *      "ssl_version" option correctly when given an invalid ssl_version option
 *       it should return ssl = NULL
 */
static int DetectSslVersionTestParse02(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse(NULL, "2.5");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.0, !");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.0, !tls1.0");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.1, tls1.1");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.1, !tls1.2");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    PASS;
}

/**
 * \test DetectSslVersionTestParse03 is a test to make sure that we parse the
 *      "ssl_version" options correctly when given valid ssl_version options
 */
static int DetectSslVersionTestParse03(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse(NULL, "SSlv3 , tls1.0");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[SSLv3].ver == SSL_VERSION_3);
    FAIL_IF_NOT(ssl->data[TLS10].ver == TLS_VERSION_10);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, " !tls1.2");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[TLS12].ver == TLS_VERSION_12);
    FAIL_IF_NOT(ssl->data[TLS12].flags & DETECT_SSL_VERSION_NEGATED);
    DetectSslVersionFree(NULL, ssl);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectSslVersion
 */
static void DetectSslVersionRegisterTests(void)
{
    UtRegisterTest("DetectSslVersionTestParse01", DetectSslVersionTestParse01);
    UtRegisterTest("DetectSslVersionTestParse02", DetectSslVersionTestParse02);
    UtRegisterTest("DetectSslVersionTestParse03", DetectSslVersionTestParse03);
}
