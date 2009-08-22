/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \author Endace Technology Limited
 */

#ifndef __CONF_H__
#define __CONF_H__

/**
 * The default log directory.
 */
#define DEFAULT_LOG_DIR "/var/log/eidps"

void ConfInit(void);
int ConfGet(char *name, char **vptr);
int ConfSet(char *name, char *val, int allow_override);
void ConfRegisterTests();

#endif /* ! __CONF_H__ */
