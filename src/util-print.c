/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "util-error.h"
#include "util-debug.h"

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
        ch = 0;
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

