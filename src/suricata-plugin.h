#ifndef __SURICATA_PLUGIN_H__
#define __SURICATA_PLUGIN_H__

#include <config.h>

#ifdef SURICATA_PLUGIN
#undef HAVE_LUA
#undef HAVE_NSS
#endif

#include "suricata-common.h"

typedef struct SCPlugin_ {
    char *name;
    char *license;
    char *author;

    void (*Init)(void);
} SCPlugin;

#endif /* __SURICATA_PLUGIN_H */
