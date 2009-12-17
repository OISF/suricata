/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \file util-daemon.h
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 */

#ifndef __UTIL_DAEMON_H__
#define __UTIL_DAEMON_H__

/** \todo Adjust path */
#define DAEMON_WORKING_DIRECTORY "/"

int CheckValidDaemonModes (int, int);
void Daemonize (void);

#endif /* __UTIL_DAEMON_H__ */
