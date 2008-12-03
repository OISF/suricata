/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void PrintRawUriFp(FILE *fp, u_int8_t *buf, u_int32_t buflen) {
    int i;
    for (i = 0; i < buflen; i++) {
        if (isprint(buf[i])) fprintf(fp, "%c", buf[i]);
        else fprintf(fp, "\\x%02X", buf[i]);
    }
}

void PrintRawDataFp(FILE *fp, u_int8_t *buf, u_int32_t buflen) {
    int i,ch = 0;

    for (i = 0; i < buflen; i+=16) {
        fprintf(fp ," %04X  ", i);
        ch = 0;
        for (ch = 0; (i+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%02X ", (u_int8_t)buf[i+ch]);

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

        ch = 0;
        for (ch = 0; (i+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%c", isprint((u_int8_t)buf[i+ch]) ? (u_int8_t)buf[i+ch] : '.');

             if (ch == 7)  fprintf(fp, " ");
             if (ch == 15) fprintf(fp, "\n");
        }
    }
    if (ch != 16)
        fprintf(fp, "\n");
}

