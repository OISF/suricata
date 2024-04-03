/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#ifndef SURICATA_UTIL_SYSTEMD_H
#define SURICATA_UTIL_SYSTEMD_H

int SystemDNotifyReady(void);

#endif /* SURICATA_UTIL_SYSTEMD_H */
