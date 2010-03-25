/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "suricata.h"

typedef struct OutputModule_ {
    char *name;
    char *conf_name;
    OutputCtx *(*InitFunc)(ConfNode *);

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;

void OutputRegisterModule(char *, char *, OutputCtx *(*)(ConfNode *));
OutputModule *OutputGetModuleByConfName(char *name);
void OutputDeregisterAll(void);

#endif /* ! __OUTPUT_H__ */
