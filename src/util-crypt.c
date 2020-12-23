/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Roliers Jean-Paul <popof.fpn@gmail.co>
 *
 * Implements cryptographic functions.
 * Based on the libtomcrypt library ( http://libtom.org/?page=features&newsitems=5&whatfile=crypt )
 * 
 * Implementation of function using NSS is not linked with libtomcrypt.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-crypt.h"

static const char *b64codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64Encode(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen)
{
   unsigned long i, len2, leven;
   unsigned char *p;
   if(in == NULL || out == NULL || outlen == NULL)
   {
       return SC_BASE64_INVALID_ARG;
   }
   /* valid output size ? */
   len2 = 4 * ((inlen + 2) / 3);
   if (*outlen < len2 + 1) {
      *outlen = len2 + 1;
      return SC_BASE64_OVERFLOW;
   }
   p = out;
   leven = 3*(inlen / 3);
   for (i = 0; i < leven; i += 3) {
       *p++ = b64codes[(in[0] >> 2) & 0x3F];
       *p++ = b64codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
       *p++ = b64codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
       *p++ = b64codes[in[2] & 0x3F];
       in += 3;
   }
   /* Pad it if necessary...  */
   if (i < inlen) {
       unsigned a = in[0];
       unsigned b = (i+1 < inlen) ? in[1] : 0;

       *p++ = b64codes[(a >> 2) & 0x3F];
       *p++ = b64codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
       *p++ = (i+1 < inlen) ? b64codes[(((b & 0xf) << 2)) & 0x3F] : '=';
       *p++ = '=';
   }
   /* append a NULL byte */
   *p = '\0';
   /* return ok */
   *outlen = p - out;
   return SC_BASE64_OK;
}
