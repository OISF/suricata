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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

/**
 * \test DetectTlsVersionTestParse01 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option
 */
static int DetectTlsVersionTestParse01 (void)
{
    DetectTlsVersionData *tls = NULL;
    tls = DetectTlsVersionParse(NULL, "1.0");
    FAIL_IF_NULL(tls);
    FAIL_IF_NOT(tls->ver == TLS_VERSION_10);
    DetectTlsVersionFree(NULL, tls);
    PASS;
}

/**
 * \test DetectTlsVersionTestParse02 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectTlsVersionTestParse02 (void)
{
    DetectTlsVersionData *tls = NULL;
    tls = DetectTlsVersionParse(NULL, "2.5");
    FAIL_IF_NOT_NULL(tls);
    DetectTlsVersionFree(NULL, tls);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTlsVersion
 */
static void DetectTlsVersionRegisterTests(void)
{
    UtRegisterTest("DetectTlsVersionTestParse01", DetectTlsVersionTestParse01);
    UtRegisterTest("DetectTlsVersionTestParse02", DetectTlsVersionTestParse02);
}
