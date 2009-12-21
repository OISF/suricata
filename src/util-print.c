/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"

void PrintRawUriFp(FILE *fp, uint8_t *buf, uint32_t buflen) {
    int i;
    for (i = 0; i < buflen; i++) {
        if (isprint(buf[i])) fprintf(fp, "%c", buf[i]);
        else fprintf(fp, "\\x%02X", buf[i]);
    }
}

void PrintRawDataFp(FILE *fp, uint8_t *buf, uint32_t buflen) {
    int i,ch = 0;

    for (i = 0; i < buflen; i+=16) {
        fprintf(fp ," %04X  ", i);
        ch = 0;
        for (ch = 0; (i+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%02X ", (uint8_t)buf[i+ch]);

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

        for (ch = 0; (i+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%c", isprint((uint8_t)buf[i+ch]) ? (uint8_t)buf[i+ch] : '.');

             if (ch == 7)  fprintf(fp, " ");
             if (ch == 15) fprintf(fp, "\n");
        }
    }
    if (ch != 16)
        fprintf(fp, "\n");
}

