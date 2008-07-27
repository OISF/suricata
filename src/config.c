
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/signal.h>
#include <errno.h>

#include <pcre.h>

#include "vips.h"

static pcre *config_pcre = NULL;
static pcre_extra *config_pcre_extra = NULL;

#define CONFIG_PCRE "^\\s*([a-z]+)\\s*(.*)$"



int LoadConfig ( void ) {
    char line[8192] = "";
    char *regexstr = CONFIG_PCRE;
    const char *eb;
    int eo;
    int opts = 0;
    int ret = 0;
#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];

    FILE *fp = fopen("vips.conf", "r");
    if (fp == NULL) printf("ERROR: fopen failed %s\n", strerror(errno));


    //opts |= PCRE_UNGREEDY;
    config_pcre = pcre_compile(regexstr, opts, &eb, &eo, NULL);
    if(config_pcre == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", regexstr, eo, eb);
        exit(1);
    }

    config_pcre_extra = pcre_study(config_pcre, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        exit(1);
    }


    while (fgets(line,sizeof(line),fp) != NULL) {
        //printf("LoadConfig: %s", line);

        ret = pcre_exec(config_pcre, config_pcre_extra, line, strlen(line), 0, 0, ov, MAX_SUBSTRINGS);
        if (ret != 3) {
            //printf("pcre_exec failed: ret %d, optstr \"%s\"\n", ret, line);
            continue;
        }
        //printf("LoadConfig: pcre_exec returned %d\n", ret);

        const char *all, *name, *value;
        pcre_get_substring(line, ov, MAX_SUBSTRINGS, 0, &all);
        pcre_get_substring(line, ov, MAX_SUBSTRINGS, 1, &name);
        pcre_get_substring(line, ov, MAX_SUBSTRINGS, 2, &value);

        printf("LoadConfig: name \"%s\" value \"%s\"\n", name, value);
    }

    return 0;
error:
    return -1;
}

