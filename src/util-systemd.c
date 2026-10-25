/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

/* this file is copied from:
 * https://github.com/systemd/systemd/blob/main/man/notify-selfcontained-example.c
 * written by Luca Boccassi */

#include "suricata-common.h"

#if (defined SYSTEMD_NOTIFY) && (defined HAVE_SYS_UN_H) && (defined HAVE_SYS_STAT_H) &&            \
        (defined HAVE_SYS_TYPES_H)
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "util-systemd.h"

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd)
{
    if (!fd || *fd < 0)
        return;

    close(*fd);
    *fd = -1;
}

/* Socket connected in advance by SystemDNotifyConnect(), -1 if there is none.
 * Only used by the main thread. */
static int notify_fd = -1;

/**
 * \brief Connect to the systemd notify socket
 *
 * \param out_fd set to the connected socket on success
 * \retval 1 if connected, 0 if there is no socket to notify, negative errno
 *         on error
 */
static int NotifyConnect(int *out_fd)
{
    union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_un sun;
    } socket_addr = {
        .sun.sun_family = AF_UNIX,
    };
    size_t path_length;
    const char *socket_path;

    socket_path = getenv("NOTIFY_SOCKET");
    if (!socket_path)
        return 0; /* Not running under systemd? Nothing to do */

    /* Only AF_UNIX is supported, with path or abstract sockets */
    if (socket_path[0] != '/' && socket_path[0] != '@')
        return -EAFNOSUPPORT;

    path_length = strlen(socket_path);
    /* Ensure there is room for NUL byte */
    if (path_length >= sizeof(socket_addr.sun.sun_path))
        return -E2BIG;

    memcpy(socket_addr.sun.sun_path, socket_path, path_length);

    /* Support for abstract socket */
    if (socket_addr.sun.sun_path[0] == '@')
        socket_addr.sun.sun_path[0] = 0;

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    if (connect(fd, &socket_addr.sa,
                offsetof(struct sockaddr_un, sun_path) + (uint32_t)path_length) != 0) {
        int err = errno;
        close(fd);
        return -err;
    }

    *out_fd = fd;
    return 1;
}

static int Notify(const char *message)
{
    size_t message_length;
    /* use the socket connected in advance if any, it is closed after use */
    _cleanup_(closep) int fd = notify_fd;
    notify_fd = -1;

    if (fd < 0) {
        int r = NotifyConnect(&fd);
        if (r <= 0)
            return r;
    }

    if (!message)
        return -EINVAL;

    message_length = strlen(message);
    if (message_length == 0)
        return -EINVAL;

    ssize_t written = write(fd, message, message_length);
    if (written != (ssize_t)message_length)
        return written < 0 ? -errno : -EPROTO;

    return 1; /* Notified! */
}

/**
 * \brief Connect to the systemd notify socket ahead of the notification
 *
 * To be called before the process is sandboxed, as connecting to the socket
 * may not be allowed afterwards. The connected socket is used and closed by
 * the next notification.
 *
 * \retval 1 if connected, 0 if there is no socket to notify, negative errno
 *         on error
 */
int SystemDNotifyConnect(void)
{
    if (notify_fd >= 0)
        return 1;
    return NotifyConnect(&notify_fd);
}

int SystemDNotifyReady(void)
{
    return Notify("READY=1");
}
#endif
