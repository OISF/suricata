/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * Implements support for tls_cipher_suite keyword.
 */

#include "ctype.h"

#include "suricata-common.h"
#include "threads.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-tls.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-memcmp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "stream-tcp.h"
#include "flow-util.h"

static int DetectTlsCipherSuiteSetup(DetectEngineCtx *, Signature *, char *);
static void DetectTlsCipherSuiteRegisterTests(void);
static int g_tls_generic_list_id = 0;

#define PARSE_REGEX  "^(client|server):(.+(:.+)*)"
static pcre *cipher_parse_regex;
static pcre_extra *cipher_parse_regex_study;

typedef struct CipherSuite_ {
    uint16_t value;
    const char *description;
} CipherSuite;

// http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
static CipherSuite g_suites[] = {
    {0x0000, "TLS_NULL_WITH_NULL_NULL" },
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0x0000, "TLS_NULL_WITH_NULL_NULL"},
    {0x0001, "TLS_RSA_WITH_NULL_MD5"},
    {0x0002, "TLS_RSA_WITH_NULL_SHA"},
    {0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
    {0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
    {0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"},
    {0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0009, "TLS_RSA_WITH_DES_CBC_SHA"},
    {0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA"},
    {0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA"},
    {0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"},
    {0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"},
    {0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
    {0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
    {0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
    {0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA"},
    {0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},
    {0x001E, "TLS_KRB5_WITH_DES_CBC_SHA"},
    {0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"},
    {0x0020, "TLS_KRB5_WITH_RC4_128_SHA"},
    {0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA"},
    {0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"},
    {0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"},
    {0x0024, "TLS_KRB5_WITH_RC4_128_MD5"},
    {0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"},
    {0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"},
    {0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"},
    {0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"},
    {0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"},
    {0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"},
    {0x002C, "TLS_PSK_WITH_NULL_SHA"},
    {0x002D, "TLS_DHE_PSK_WITH_NULL_SHA"},
    {0x002E, "TLS_RSA_PSK_WITH_NULL_SHA"},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"},
    {0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"},
    {0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"},
    {0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
    {0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"},
    {0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"},
    {0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"},
    {0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
    {0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"},
    {0x003B, "TLS_RSA_WITH_NULL_SHA256"},
    {0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
    {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
    {0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"},
    {0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"},
    {0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"},
    {0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"},
    {0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"},
    {0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"},
    {0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},
    {0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"},
    {0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"},
    {0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"},
    {0x008A, "TLS_PSK_WITH_RC4_128_SHA"},
    {0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA"},
    {0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA"},
    {0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA"},
    {0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"},
    {0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"},
    {0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"},
    {0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"},
    {0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"},
    {0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"},
    {0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA"},
    {0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA"},
    {0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"},
    {0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"},
    {0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA"},
    {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"},
    {0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"},
    {0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"},
    {0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"},
    {0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"},
    {0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"},
    {0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"},
    {0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"},
    {0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B0, "TLS_PSK_WITH_NULL_SHA256"},
    {0x00B1, "TLS_PSK_WITH_NULL_SHA384"},
    {0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256"},
    {0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384"},
    {0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256"},
    {0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384"},
    {0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
    {0x5600, "TLS_FALLBACK_SCSV"},
    {0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"},
    {0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"},
    {0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
    {0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
    {0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA"},
    {0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA"},
    {0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"},
    {0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"},
    {0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"},
    {0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
    {0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {0xC015, "TLS_ECDH_anon_WITH_NULL_SHA"},
    {0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
    {0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"},
    {0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},
    {0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
    {0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"},
    {0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"},
    {0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"},
    {0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"},
    {0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"},
    {0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"},
    {0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"},
    {0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"},
    {0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"},
    {0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"},
    {0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"},
    {0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"},
    {0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA"},
    {0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256"},
    {0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384"},
    {0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"},
    {0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"},
    {0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"},
    {0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"},
    {0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"},
    {0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"},
    {0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"},
    {0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"},
    {0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"},
    {0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"},
    {0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"},
    {0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"},
    {0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC09C, "TLS_RSA_WITH_AES_128_CCM"},
    {0xC09D, "TLS_RSA_WITH_AES_256_CCM"},
    {0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM"},
    {0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM"},
    {0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8"},
    {0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8"},
    {0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"},
    {0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"},
    {0xC0A4, "TLS_PSK_WITH_AES_128_CCM"},
    {0xC0A5, "TLS_PSK_WITH_AES_256_CCM"},
    {0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM"},
    {0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM"},
    {0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8"},
    {0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8"},
    {0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8"},
    {0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8"},
    {0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
    {0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"},
    {0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"},
    {0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"},
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xFFFF, "" }

};

typedef struct DetectTlsCipherSuiteData_ {
    uint32_t direction;         /**< STREAM_TOSERVER or STREAM_TOCLIENT */
    uint32_t length;            /** < Number of cipher suites */
    uint16_t *ciphersuite;      /** < The lit of cipher suites */
} DetectTlsCipherSuiteData;

void DetectTlsCipherSuiteFree(void *data)
{
    if (data == NULL)
        return;

    DetectTlsCipherSuiteData *cipher = data;
    SCFree(cipher);
    data = NULL;
}

/**
 * \brief gets a cipher suite description
 *
 * \param value - 2 bytes value for cipher suite code
 *
 * \retval "-" if not found
 * \retval const char * with description if found
 */
const char * TlsCipherSuiteDescription(uint16_t value)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t I = value;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t I = (value >>8) | (value<<8);
#endif
    for (size_t i = 0; sizeof(g_suites); ++i) {
        if (g_suites[i].value == I)
             return g_suites[i].description;
        if (g_suites[i].value == 0xFFFF)
             return g_suites[i].description;
    }
    return "-";
}

/**
 * \brief match the specified cipher suite for handshake side on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */

//
static int DetectTlsCipherSuiteMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();
    DetectTlsCipherSuiteData *data = (DetectTlsCipherSuiteData *)m;

    if (data == NULL) {
        SCReturnInt(0);
    }
    if (! (data->direction & flags)) {
        SCReturnInt(0);
    }
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }
    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->num_cipher_suites > 0 && data->length > 0) {
        for (uint32_t j=0; j < data->length; ++j) {
            for (uint32_t i=0; i < connp->num_cipher_suites; ++i) {
#if __BYTE_ORDER == __BIG_ENDIAN
                uint16_t I = connp->cipher_suites[i];
#elif __BYTE_ORDER == __LITTLE_ENDIAN
                uint16_t I = (connp->cipher_suites[i]>>8) | (connp->cipher_suites[i]<<8);
#endif
                uint16_t J = data->ciphersuite[j];
                SCLogDebug("** CHECK ** (%d) I:[%04X]/%d:%d J:[%04X]/%d:%d",
                        data->direction, I, i, connp->num_cipher_suites,
                        J, j, data->length);
                if (I == J) {
                    SCLogDebug("** MATCHED ** (%d) I:[%04X]/%d J:[%04X]/%d",
                            data->direction, I, i, J, j );
                    SCReturnInt(1);
                }
            }
        }
    }
    SCReturnInt(0);
}

/**
 * \brief Registration function for keyword: tls_cipher_suite
 */
void DetectTlsCipherSuiteRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].name = "tls_cipher_suite";
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].desc = "match SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2 Cipher Suites";
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].url = DOC_URL DOC_VERSION "/rules/tls-keywords.html#cipher.suite";
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].AppLayerTxMatch = DetectTlsCipherSuiteMatch;
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].Setup = DetectTlsCipherSuiteSetup;
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].Free  = DetectTlsCipherSuiteFree;
    sigmatch_table[DETECT_AL_TLS_CIPHER_SUITE].RegisterTests = DetectTlsCipherSuiteRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX,
            &cipher_parse_regex, &cipher_parse_regex_study);

    g_tls_generic_list_id = DetectBufferTypeRegister("tls_generic");
}

static uint16_t TlsCipherSuiteNumLisEntries(const char *str) {

    if (str == NULL){
        return 0;
    }

    uint16_t ret = 1;
    size_t len = strlen(str);
    char *ptr = (char *)str;

    for (size_t i=0; i < len; ++i) {
        if (*ptr == ':') {
            ++ret;
        }
        ++ptr;
    }
    return ret;
}

static DetectTlsCipherSuiteData *DetectTlsCipherSuiteParse (char *str)
{
    static const char * g_list_delimiter = ":";
    DetectTlsCipherSuiteData *data = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS] = { 0 };
    const char *side_str = NULL;
    const char *list_str = NULL;

    ret = pcre_exec(cipher_parse_regex, cipher_parse_regex_study,
                    str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid cipher.suite option: %d", ret);
        goto error;
    }

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &side_str);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 2, &list_str);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    uint32_t direction = 0 ;

    if (SCMemcmp("client", side_str, 6) == 0) {
        direction = STREAM_TOSERVER;
    } else if (SCMemcmp("server", side_str, 6) == 0) {
        direction = STREAM_TOCLIENT;
    } else {
        SCLogError(SC_ERR_PCRE_MATCH,
                "Invalid side for cipher: specify server or client");
        goto side_error;
    }

    /* We have a correct id option */
    data = SCMalloc(sizeof(DetectTlsCipherSuiteData));
    if (unlikely(data == NULL))
        goto side_error;

    data->direction = direction;
    data->length = TlsCipherSuiteNumLisEntries(list_str);

    if (!data->length) {
        goto side_error;
    }

    data->ciphersuite = SCMalloc(sizeof(uint16_t) * data->length);
    if(unlikely(data->ciphersuite == NULL)) {
        goto side_error;
    }

    size_t g_suites_len = 0;
    SSLCipherSuite * g_suites = SSLCipherSuites(&g_suites_len);

    /* Parse cipher suite list */
    char *saved = NULL;
    char *pch = strtok_r((char *)list_str, g_list_delimiter, &saved);
    size_t rule_suite_index = 0;
    while (pch != NULL) {
        /* Insert value if is hex value 0x0000 */
        if (strlen(pch) == 6) {
            if (pch[0] == '0' && pch[1] == 'x'
                && isxdigit(pch[2]) && isxdigit(pch[3])
                && isxdigit(pch[4]) && isxdigit(pch[5])) {

                uint16_t value = (int)strtol(pch, NULL, 16);
                data->ciphersuite[rule_suite_index] = value;
                ++rule_suite_index;
                break;
            }
        }

        /* Find by description */
        for (size_t i=0; i < g_suites_len; ++i) {
            if ( SCMemcmp(pch, g_suites[i].description, strlen(g_suites[i].description)) == 0 ) {
                data->ciphersuite[rule_suite_index] = g_suites[i].value;
                ++rule_suite_index;
                break;
            }
        }
        pch = strtok_r(NULL, g_list_delimiter, &saved);
    }

    pcre_free_substring(side_str);
    pcre_free_substring(list_str);
    return data;
side_error:
    pcre_free_substring(side_str);
    pcre_free_substring(list_str);
error:
    if (data != NULL)
        DetectTlsCipherSuiteFree(data);
    return NULL;
}


/**
 * \brief this function setup the cipher.suite modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectTlsCipherSuiteSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectTlsCipherSuiteData *data = NULL;
    SigMatch *sm = NULL;

    data = DetectTlsCipherSuiteParse(str);
    if (data == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_TLS_CIPHER_SUITE;
    sm->ctx = (SigMatchCtx *) data;

    s->flags |= SIG_FLAG_APPLAYER;
    s->flags |= data->direction;
    s->alproto = ALPROTO_TLS;

    SigMatchAppendSMToList(s, sm, g_tls_generic_list_id);

    return 0;
error:
    if (data != NULL)
        DetectTlsCipherSuiteFree(data);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

#ifdef UNITTESTS

/**
 * \test Test that signatures containing a tls_cipher_suite are correctly parsed
 *       and that the keyword is registered.
 */
static int DetectTlsCipherSuiteClientTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tls any any -> any any "
                               "(msg:\"Testing client tls_cipher_suite\"; "
                               "tls_cipher_suite:client:0x0000; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test that signatures containing a tls_cipher_suite are correctly parsed
 *       and that the keyword is registered.
 */
static int DetectTlsCipherSuiteServerTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tls any any -> any any "
                               "(msg:\"Testing server tls_cipher_suite\"; "
                               "tls_cipher_suite:server:h2; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test that tls_cipher_suite with a bad handshake side
 */
static int DetectTlsCipherSuiteBadSideTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tls any any -> any any "
                               "(msg:\"Testing trudy tls_cipher_suite\"; "
                               "tls_cipher_suite:trudy:0x0000; sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test that match tls_cipher_suite
 */
static int DetectTlsCipherSuiteMatchTest04(void)
{
    /* client hello */

    uint8_t client_hello[] = {
                    0x16, 0x03, 0x01, 0x01, 0x12, 0x01, /*   ...... */
        0x00, 0x01, 0x0e, 0x03, 0x03, 0x58, 0x39, 0x81, /* .....X9. */
        0xf2, 0x6d, 0x3c, 0x03, 0x7c, 0xb0, 0x44, 0x8c, /* .m<.|.D. */
        0x08, 0x25, 0x5d, 0xed, 0x48, 0x8c, 0x35, 0x72, /* .%].H.5r */
        0x6d, 0x38, 0xfc, 0x30, 0x74, 0x5e, 0x97, 0x24, /* m8.0t^.$ */
        0xa3, 0x4e, 0x22, 0x5b, 0x78, 0x00, 0x00, 0x72, /* .N"[x..r */
        0xc0, 0x2c, 0xc0, 0x87, 0xcc, 0xa9, 0xc0, 0xad, /* .,...... */
        0xc0, 0x0a, 0xc0, 0x24, 0xc0, 0x73, 0xc0, 0x2b, /* ...$.s.+ */
        0xc0, 0x86, 0xc0, 0xac, 0xc0, 0x09, 0xc0, 0x23, /* .......# */
        0xc0, 0x72, 0xc0, 0x08, 0xc0, 0x30, 0xc0, 0x8b, /* .r...0.. */
        0xcc, 0xa8, 0xc0, 0x14, 0xc0, 0x28, 0xc0, 0x77, /* .....(.w */
        0xc0, 0x2f, 0xc0, 0x8a, 0xc0, 0x13, 0xc0, 0x27, /* ./.....' */
        0xc0, 0x76, 0xc0, 0x12, 0x00, 0x9d, 0xc0, 0x7b, /* .v.....{ */
        0xc0, 0x9d, 0x00, 0x35, 0x00, 0x3d, 0x00, 0x84, /* ...5.=.. */
        0x00, 0xc0, 0x00, 0x9c, 0xc0, 0x7a, 0xc0, 0x9c, /* .....z.. */
        0x00, 0x2f, 0x00, 0x3c, 0x00, 0x41, 0x00, 0xba, /* ./.<.A.. */
        0x00, 0x0a, 0x00, 0x9f, 0xc0, 0x7d, 0xcc, 0xaa, /* .....}.. */
        0xc0, 0x9f, 0x00, 0x39, 0x00, 0x6b, 0x00, 0x88, /* ...9.k.. */
        0x00, 0xc4, 0x00, 0x9e, 0xc0, 0x7c, 0xc0, 0x9e, /* .....|.. */
        0x00, 0x33, 0x00, 0x67, 0x00, 0x45, 0x00, 0xbe, /* .3.g.E.. */
        0x00, 0x16, 0x01, 0x00, 0x00, 0x73, 0x00, 0x17, /* .....s.. */
        0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x05, /* ........ */
        0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
        0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, /* ........ */
        0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, /* www.goog */
        0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01, /* le.com.. */
        0x00, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, /* ....#... */
        0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x17, 0x00, /* ........ */
        0x18, 0x00, 0x19, 0x00, 0x15, 0x00, 0x13, 0x00, /* ........ */
        0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, /* ........ */
        0x16, 0x00, 0x14, 0x04, 0x01, 0x04, 0x03, 0x05, /* ........ */
        0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x03, /* ........ */
        0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03, 0x00, /* ........ */
        0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, /* ......h2 */
        0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, /* .http/1. */
        0x31                                            /* 1 */
    };


    /* server hello */
    uint8_t server_hello[] = {
                    0x16, 0x03, 0x03, 0x00, 0x4c, 0x02, /*   ....L. */
        0x00, 0x00, 0x48, 0x03, 0x03, 0x58, 0x39, 0x81, /* ..H..X9. */
        0x84, 0x0d, 0x2b, 0x71, 0xce, 0x16, 0x57, 0xe0, /* ..+q..W. */
        0x67, 0x1d, 0x7b, 0x69, 0x41, 0xf6, 0x9e, 0xc0, /* g.{iA... */
        0x1d, 0xb3, 0x2f, 0x6d, 0xd2, 0xd2, 0x6a, 0x2d, /* ../m..j- */
        0xda, 0x17, 0x96, 0xfd, 0xb2, 0x00, 0xcc, 0xa8, /* ........ */
        0x00, 0x00, 0x20, 0xff, 0x01, 0x00, 0x01, 0x00, /* .. ..... */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, /* ........ */
        0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, /* .#...... */
        0x00, 0x03, 0x02, 0x68, 0x32, 0x00, 0x0b, 0x00, /* ...h2... */
        0x02, 0x01, 0x00, 0x16, 0x03, 0x03, 0x0c, 0x09, /* ........ */
        0x0b, 0x00, 0x0c, 0x05, 0x00, 0x0c, 0x02, 0x00, /* ........ */
        0x04, 0x84, 0x30, 0x82, 0x04, 0x80, 0x30, 0x82, /* ..0...0. */
        0x03, 0x68, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, /* .h...... */
        0x08, 0x44, 0xb8, 0x48, 0xca, 0xa0, 0x5a, 0x08, /* .D.H..Z. */
        0x83, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, /* .0...*.H */
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, /* ........ */
        0x30, 0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, /* 0I1.0... */
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, /* U....US1 */
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, /* .0...U.. */
        0x13, 0x0a, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, /* ..Google */
        0x20, 0x49, 0x6e, 0x63, 0x31, 0x25, 0x30, 0x23, /*  Inc1%0# */
        0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1c, 0x47, /* ..U....G */
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, /* oogle In */
        0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x41, /* ternet A */
        0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, /* uthority */
        0x20, 0x47, 0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, /*  G20...1 */
        0x36, 0x31, 0x31, 0x31, 0x30, 0x31, 0x35, 0x33, /* 61110153 */
        0x31, 0x33, 0x38, 0x5a, 0x17, 0x0d, 0x31, 0x37, /* 138Z..17 */
        0x30, 0x32, 0x30, 0x32, 0x31, 0x35, 0x33, 0x30, /* 02021530 */
        0x30, 0x30, 0x5a, 0x30, 0x68, 0x31, 0x0b, 0x30, /* 00Z0h1.0 */
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, /* ...U.... */
        0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, /* US1.0... */
        0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, /* U....Cal */
        0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, /* ifornia1 */
        0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, /* .0...U.. */
        0x0c, 0x0d, 0x4d, 0x6f, 0x75, 0x6e, 0x74, 0x61, /* ..Mounta */
        0x69, 0x6e, 0x20, 0x56, 0x69, 0x65, 0x77, 0x31, /* in View1 */
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, /* .0...U.. */
        0x0c, 0x0a, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, /* ..Google */
        0x20, 0x49, 0x6e, 0x63, 0x31, 0x17, 0x30, 0x15, /*  Inc1.0. */
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x77, /* ..U....w */
        0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* ww.googl */
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x01, /* e.com0.. */
        0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, /* "0...*.H */
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, /* ........ */
        0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, /* .....0.. */
        0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x97, 0xa4, /* ........ */
        0x10, 0xac, 0xbc, 0xd8, 0xd2, 0x32, 0xaf, 0x6c, /* .....2.l */
        0x7f, 0xcb, 0xfc, 0x46, 0x2b, 0x8c, 0x5e, 0xe1, /* ...F+.^. */
        0x0a, 0x47, 0xbd, 0x82, 0x3f, 0x0c, 0xf3, 0x42, /* .G..?..B */
        0xa8, 0xcb, 0xea, 0x0c, 0x45, 0xfe, 0x1d, 0xa4, /* ....E... */
        0xd6, 0x83, 0x63, 0x9e, 0x6d, 0x03, 0xe6, 0x94, /* ..c.m... */
        0x6f, 0x1d, 0xc2, 0x68, 0x28, 0x9f, 0x35, 0x7e, /* o..h(.5~ */
        0x27, 0x59, 0x22, 0xf5, 0x8a, 0x4e, 0xd4, 0x1a, /* 'Y"..N.. */
        0xab, 0xa2, 0xe8, 0x13, 0x81, 0xf9, 0x5f, 0xdd, /* ......_. */
        0x92, 0x0e, 0x4f, 0x7e, 0x12, 0xec, 0xfc, 0xd7, /* ..O~.... */
        0xb7, 0x4b, 0x39, 0xe4, 0x03, 0x50, 0xc2, 0xd0, /* .K9..P.. */
        0xe2, 0xf9, 0xf2, 0x22, 0xc4, 0x3e, 0x87, 0xfa, /* ...".>.. */
        0xc9, 0x98, 0xb7, 0xd6, 0x4c, 0xd4, 0xa5, 0xee, /* ....L... */
        0xf5, 0xdf, 0x37, 0x20, 0x63, 0x6e, 0x4d, 0xa4, /* ..7 cnM. */
        0x8a, 0x27, 0xe8, 0xf8, 0xa7, 0x7e, 0x2c, 0x95, /* .'...~,. */
        0x4f, 0xdb, 0x59, 0x22, 0xc5, 0x7b, 0x62, 0x9a, /* O.Y".{b. */
        0xd5, 0x7d, 0x30, 0x9d, 0x1c, 0x5f, 0x0f, 0x47, /* .}0.._.G */
        0xd5, 0x34, 0x9c, 0xa8, 0x69, 0xd3, 0xbb, 0xe5, /* .4..i... */
        0x04, 0x45, 0xd5, 0x4c, 0x70, 0x1f, 0xe4, 0x4d, /* .E.Lp..M */
        0x84, 0xfe, 0x5b, 0x81, 0x86, 0x61, 0xc9, 0xa3, /* ..[..a.. */
        0xc7, 0xcf, 0x70, 0xc3, 0x6c, 0xde, 0x44, 0x06, /* ..p.l.D. */
        0x9e, 0xe7, 0xa0, 0xe5, 0x61, 0xa2, 0xe7, 0x85, /* ....a... */
        0xb4, 0x81, 0xa0, 0x95, 0xe2, 0x35, 0xcf, 0xbf, /* .....5.. */
        0x1e, 0x1e, 0x68, 0xce, 0xb5, 0x7b, 0xac, 0x8f, /* ..h..{.. */
        0x44, 0xfe, 0x50, 0x8b, 0x5b, 0x37, 0x18, 0xf1, /* D.P.[7.. */
        0x33, 0x0a, 0x20, 0x08, 0x26, 0x7a, 0xa4, 0xed, /* 3. .&z.. */
        0x15, 0x38, 0xc5, 0x6f, 0x5e, 0x53, 0x8a, 0xba, /* .8.o^S.. */
        0x8d, 0x0c, 0x35, 0x87, 0x97, 0xc1, 0x7a, 0xf9, /* ..5...z. */
        0xf2, 0xdf, 0xd0, 0x01, 0x7b, 0x0c, 0x2c, 0x2e, /* ....{.,. */
        0x35, 0x8b, 0x49, 0xbb, 0x9d, 0xfd, 0x88, 0xb3, /* 5.I..... */
        0x37, 0x43, 0xab, 0x4d, 0x51, 0x09, 0x75, 0x69, /* 7C.MQ.ui */
        0x67, 0x59, 0x43, 0x5d, 0xdc, 0xe8, 0x2f, 0xaa, /* gYC]../. */
        0x52, 0xa6, 0xc6, 0xf2, 0x48, 0xa7, 0x02, 0x03, /* R...H... */
        0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x4b, 0x30, /* ......K0 */
        0x82, 0x01, 0x47, 0x30, 0x1d, 0x06, 0x03, 0x55, /* ..G0...U */
        0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, /* .%..0... */
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, /* +....... */
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, /* ..+..... */
        0x03, 0x02, 0x30, 0x19, 0x06, 0x03, 0x55, 0x1d, /* ..0...U. */
        0x11, 0x04, 0x12, 0x30, 0x10, 0x82, 0x0e, 0x77, /* ...0...w */
        0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* ww.googl */
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x68, 0x06, /* e.com0h. */
        0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, /* .+...... */
        0x01, 0x04, 0x5c, 0x30, 0x5a, 0x30, 0x2b, 0x06, /* ..\0Z0+. */
        0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, /* .+.....0 */
        0x02, 0x86, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x3a, /* ...http: */
        0x2f, 0x2f, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, /* //pki.go */
        0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, /* ogle.com */
        0x2f, 0x47, 0x49, 0x41, 0x47, 0x32, 0x2e, 0x63, /* /GIAG2.c */
        0x72, 0x74, 0x30, 0x2b, 0x06, 0x08, 0x2b, 0x06, /* rt0+..+. */
        0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x1f, /* ....0... */
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, /* http://c */
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x31, 0x2e, /* lients1. */
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, /* google.c */
        0x6f, 0x6d, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x30, /* om/ocsp0 */
        0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, /* ...U.... */
        0x04, 0x14, 0x07, 0x9c, 0x42, 0x39, 0xad, 0x00, /* ....B9.. */
        0x94, 0x52, 0xa9, 0xa8, 0x93, 0x4e, 0x11, 0xe3, /* .R...N.. */
        0x55, 0xbf, 0x3a, 0x9b, 0xa4, 0xfa, 0x30, 0x0c, /* U.:...0. */
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, /* ..U..... */
        0x04, 0x02, 0x30, 0x00, 0x30, 0x1f, 0x06, 0x03, /* ..0.0... */
        0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, /* U.#..0.. */
        0x14, 0x4a, 0xdd, 0x06, 0x16, 0x1b, 0xbc, 0xf6, /* .J...... */
        0x68, 0xb5, 0x76, 0xf5, 0x81, 0xb6, 0xbb, 0x62, /* h.v....b */
        0x1a, 0xba, 0x5a, 0x81, 0x2f, 0x30, 0x21, 0x06, /* ..Z./0!. */
        0x03, 0x55, 0x1d, 0x20, 0x04, 0x1a, 0x30, 0x18, /* .U. ..0. */
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, /* 0...+... */
        0x01, 0xd6, 0x79, 0x02, 0x05, 0x01, 0x30, 0x08, /* ..y...0. */
        0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x02, /* ..g..... */
        0x30, 0x30, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, /* 00..U... */
        0x29, 0x30, 0x27, 0x30, 0x25, 0xa0, 0x23, 0xa0, /* )0'0%.#. */
        0x21, 0x86, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x3a, /* !..http: */
        0x2f, 0x2f, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, /* //pki.go */
        0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, /* ogle.com */
        0x2f, 0x47, 0x49, 0x41, 0x47, 0x32, 0x2e, 0x63, /* /GIAG2.c */
        0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, /* rl0...*. */
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, /* H....... */
        0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x68, 0x04, /* ......h. */
        0x32, 0xc9, 0x32, 0x70, 0xea, 0x0e, 0x37, 0x4e, /* 2.2p..7N */
        0xb6, 0xa8, 0x32, 0xa5, 0xa6, 0x4f, 0x5d, 0xb5, /* ..2..O]. */
        0x68, 0x9b, 0xd3, 0xf0, 0x35, 0xce, 0x53, 0x22, /* h...5.S" */
        0x28, 0x28, 0x28, 0x7a, 0x4f, 0x24, 0x0e, 0xff, /* (((zO$.. */
        0xfc, 0x5b, 0xf6, 0x97, 0xd7, 0x83, 0xdf, 0x12, /* .[...... */
        0xaa, 0xbb, 0x1f, 0xaa, 0x70, 0x07, 0xb7, 0xfe, /* ....p... */
        0x41, 0x51, 0x78, 0x0c, 0x5a, 0x3e, 0x7d, 0xf4, /* AQx.Z>}. */
        0x89, 0x19, 0x9d, 0xfd, 0xcf, 0xc9, 0x33, 0x9b, /* ......3. */
        0x3d, 0x94, 0xd2, 0x04, 0xd6, 0xd4, 0x27, 0x96, /* =.....'. */
        0xfc, 0x18, 0xc1, 0xdf, 0x55, 0x43, 0x5d, 0x06, /* ....UC]. */
        0x18, 0x99, 0xbc, 0x5e, 0x27, 0x86, 0xce, 0x73, /* ...^'..s */
        0x7f, 0xa4, 0x34, 0x04, 0xde, 0x58, 0xbc, 0x76, /* ..4..X.v */
        0x5e, 0x9e, 0x9c, 0x3e, 0xda, 0x73, 0x74, 0x0c, /* ^..>.st. */
        0xee, 0xfc, 0xf4, 0xec, 0x48, 0xd2, 0xe5, 0xc5, /* ....H... */
        0x33, 0x52, 0x93, 0xbf, 0x28, 0xfb, 0x4c, 0xa0, /* 3R..(.L. */
        0x1a, 0xdd, 0x03, 0xc4, 0x58, 0xf3, 0x75, 0x07, /* ....X.u. */
        0x4c, 0xb0, 0xc8, 0x22, 0xcc, 0xec, 0x07, 0x4b, /* L.."...K */
        0xdb, 0xb7, 0xfb, 0x5d, 0x6e, 0x8b, 0xb1, 0x1f, /* ...]n... */
        0xcd, 0x3d, 0x6d, 0x6a, 0xa1, 0x7f, 0x58, 0x46, /* .=mj..XF */
        0x1d, 0x9f, 0xdc, 0x9f, 0xc6, 0xcf, 0x2e, 0xa9, /* ........ */
        0x0c, 0x9b, 0xdf, 0xfe, 0xbd, 0xc5, 0x95, 0x0e, /* ........ */
        0x3d, 0x95, 0x93, 0xab, 0x45, 0xff, 0x09, 0x6c, /* =...E..l */
        0x61, 0x96, 0x0a, 0xd0, 0x5f, 0x90, 0xd5, 0x65, /* a..._..e */
        0x2c, 0x5d, 0x03, 0x0b, 0xa5, 0x33, 0xcd, 0x2c, /* ,]...3., */
        0x88, 0x9f, 0x14, 0xd6, 0x20, 0xfc, 0x60, 0x03, /* .... .`. */
        0x05, 0x2e, 0x58, 0xe0, 0x68, 0x67, 0x2b, 0x49, /* ..X.hg+I */
        0x2a, 0x5a, 0x35, 0xf4, 0xdb, 0x58, 0xf6, 0x2e, /* *Z5..X.. */
        0x0b, 0xcb, 0x57, 0x0c, 0x5e, 0xdd, 0x4d, 0x7e, /* ..W.^.M~ */
        0xf2, 0x20, 0x56, 0x3f, 0x88, 0x6e, 0x66, 0xa5, /* . V?.nf. */
        0x3c, 0xaf, 0xd6, 0x0f, 0x69, 0x53, 0xc6, 0x35, /* <...iS.5 */
        0x74, 0x2d, 0x7b, 0x60, 0xab, 0x3e, 0x16, 0x2e, /* t-{`.>.. */
        0x16, 0xce, 0xb1, 0xe8, 0x17, 0x5b, 0x00, 0x03, /* .....[.. */
        0xf4, 0x30, 0x82, 0x03, 0xf0, 0x30, 0x82, 0x02, /* .0...0.. */
        0xd8, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, /* ........ */
        0x02, 0x3a, 0x92, 0x30, 0x0d, 0x06, 0x09, 0x2a, /* .:.0...* */
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, /* .H...... */
        0x05, 0x00, 0x30, 0x42, 0x31, 0x0b, 0x30, 0x09, /* ..0B1.0. */
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, /* ..U....U */
        0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, /* S1.0...U */
        0x04, 0x0a, 0x13, 0x0d, 0x47, 0x65, 0x6f, 0x54, /* ....GeoT */
        0x72, 0x75, 0x73, 0x74, 0x20, 0x49, 0x6e, 0x63, /* rust Inc */
        0x2e, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, /* .1.0...U */
        0x04, 0x03, 0x13, 0x12, 0x47, 0x65, 0x6f, 0x54, /* ....GeoT */
        0x72, 0x75, 0x73, 0x74, 0x20, 0x47, 0x6c, 0x6f, /* rust Glo */
        0x62, 0x61, 0x6c, 0x20, 0x43, 0x41, 0x30, 0x1e, /* bal CA0. */
        0x17, 0x0d, 0x31, 0x35, 0x30, 0x34, 0x30, 0x31, /* ..150401 */
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, /* 000000Z. */
        0x0d, 0x31, 0x37, 0x31, 0x32, 0x33, 0x31, 0x32, /* .1712312 */
        0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x49, /* 35959Z0I */
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, /* 1.0...U. */
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, /* ...US1.0 */
        0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, /* ...U.... */
        0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, /* Google I */
        0x6e, 0x63, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, /* nc1%0#.. */
        0x55, 0x04, 0x03, 0x13, 0x1c, 0x47, 0x6f, 0x6f, /* U....Goo */
        0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65, /* gle Inte */
        0x72, 0x6e                                      /* rn */
        };

    Flow f;
    SSLState *ssl_state = NULL;
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Signature *s_c = NULL;
    Signature *s_s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacketReal(client_hello, sizeof(client_hello), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1", 51251, 443);
    p2 = UTHBuildPacketReal(server_hello, sizeof(server_hello), IPPROTO_TCP,
                            "192.168.1.1", "192.168.1.5", 443, 51251);
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_TLS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->pcap_cnt = 2;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    s_c = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test client tls_cipher_suite\"; "
                              "tls_cipher_suite:client:0xcca8;"
                              "sid:1;)");
    FAIL_IF_NULL(s_c);

    s_s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test server tls_cipher_suite\"; "
                              "tls_cipher_suite:server:0xcca8;"
                              "sid:2;)");
    FAIL_IF_NULL(s_s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, client_hello,
                                sizeof(client_hello));
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketAlertCheck(p1, 1) == 1);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello, sizeof(server_hello));
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(r != 0);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 2) == 1);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);

    PASS;
}
#endif

static void DetectTlsCipherSuiteRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTlsCipherSuiteClientTest01", DetectTlsCipherSuiteClientTest01);
    UtRegisterTest("DetectTlsCipherSuiteServerTest02", DetectTlsCipherSuiteServerTest02);
    UtRegisterTest("DetectTlsCipherSuiteBadSideTest03", DetectTlsCipherSuiteBadSideTest03);
    UtRegisterTest("DetectTlsCipherSuiteMatchTest04", DetectTlsCipherSuiteMatchTest04);
#endif
}
