/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \author Endace Technology Limited
 */

#ifndef __CONF_H__
#define __CONF_H__

#include <inttypes.h>

/**
 * The default log directory.
 */
#define DEFAULT_LOG_DIR "/var/log/eidps"

void ConfInit(void);
int ConfGet(char *name, char **vptr);
int ConfGetInt(char *name, intmax_t *val);
int ConfGetBool(char *name, int *val);

int ConfSet(char *name, char *val, int allow_override);
void ConfDump(void);
void ConfRegisterTests();

#endif /* ! __CONF_H__ */
