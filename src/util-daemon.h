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

#ifdef OS_WIN32
#define Daemonize()
#else
void Daemonize (void);
#endif

int CheckValidDaemonModes (int, int);

#endif /* __UTIL_DAEMON_H__ */
