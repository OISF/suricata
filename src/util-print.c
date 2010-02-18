/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "util-error.h"
#include "util-debug.h"
#include "htp/bstr.h"

void PrintRawUriFp(FILE *fp, uint8_t *buf, uint32_t buflen)
{
    uint32_t u;
    bstr *uri_buf;
    char temp[5] = "";
    uri_buf = bstr_alloc(buflen + 20);  /* XXX any sane number ? to accommodate
                                           the non-printable chars, so that we
                                           dont need to reallocate, if there are
                                           less non-printable chars */
    if (uri_buf == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        return;
    }
    for (u = 0; u < buflen; u++) {
        if (isprint(buf[u])) {
            bstr_add_mem(uri_buf, (char *)&buf[u], 1);
        } else {
            snprintf(temp, sizeof(temp), "\\x%02X", buf[u]);
            bstr_add_cstr(uri_buf, temp);
        }
    }
    fprintf(fp, "%s", bstr_tocstr(uri_buf));
    bstr_free(uri_buf);
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

