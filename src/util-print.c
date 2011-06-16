/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Print utility functions
 */

#include "suricata-common.h"
#include "util-error.h"
#include "util-debug.h"

/**
 *  \brief print a buffer as hex on a single line
 *
 *  Prints in the format "00 AA BB"
 *
 *  \param fp FILE pointer to print to
 *  \param buf buffer to print from
 *  \param buflen length of the input buffer
 */
void PrintRawLineHexFp(FILE *fp, uint8_t *buf, uint32_t buflen)
{
    char nbuf[2048] = "";
    char temp[5] = "";
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        snprintf(temp, sizeof(temp), "%02X ", buf[u]);
        strlcat(nbuf, temp, sizeof(nbuf));
    }
    fprintf(fp, "%s", nbuf);
}

void PrintRawUriFp(FILE *fp, uint8_t *buf, uint32_t buflen)
{
    char nbuf[2048] = "";
    char temp[5] = "";
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        if (isprint(buf[u])) {
            snprintf(temp, sizeof(temp), "%c", buf[u]);
        } else {
            snprintf(temp, sizeof(temp), "\\x%02X", buf[u]);
        }
        strlcat(nbuf, temp, sizeof(nbuf));
    }
    fprintf(fp, "%s", nbuf);
}

void PrintRawDataFp(FILE *fp, uint8_t *buf, uint32_t buflen) {
    int ch = 0;
    uint32_t u = 0;

    for (u = 0; u < buflen; u+=16) {
        fprintf(fp ," %04X  ", u);
        for (ch = 0; (u+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%02X ", (uint8_t)buf[u+ch]);

             if (ch == 7) fprintf(fp, " ");
        }
        if (ch == 16) fprintf(fp, "  ");
        else if (ch < 8) {
            int spaces = (16 - ch) * 3 + 2 + 1;
            int s = 0;
            for ( ; s < spaces; s++) fprintf(fp, " ");
        } else if(ch < 16) {
            int spaces = (16 - ch) * 3 + 2;
            int s = 0;
            for ( ; s < spaces; s++) fprintf(fp, " ");
        }

        for (ch = 0; (u+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%c", isprint((uint8_t)buf[u+ch]) ? (uint8_t)buf[u+ch] : '.');

             if (ch == 7)  fprintf(fp, " ");
             if (ch == 15) fprintf(fp, "\n");
        }
    }
    if (ch != 16)
        fprintf(fp, "\n");
}

