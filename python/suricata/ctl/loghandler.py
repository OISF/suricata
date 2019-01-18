# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2016 Jason Ish
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

import logging
import time

GREEN = "\x1b[32m"
BLUE = "\x1b[34m"
REDB = "\x1b[1;31m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
YELLOWB = "\x1b[1;33m"
ORANGE = "\x1b[38;5;208m"
RESET = "\x1b[0m"

# A list of secrets that will be replaced in the log output.
secrets = {}

def add_secret(secret, replacement):
    """Register a secret to be masked. The secret will be replaced with:
           <replacement>
    """
    secrets[str(secret)] = str(replacement)

class SuriColourLogHandler(logging.StreamHandler):
    """An alternative stream log handler that logs with Suricata inspired
    log colours."""

    def formatTime(self, record):
        lt = time.localtime(record.created)
        t = "%d/%d/%d -- %02d:%02d:%02d" % (lt.tm_mday,
                                            lt.tm_mon,
                                            lt.tm_year,
                                            lt.tm_hour,
                                            lt.tm_min,
                                            lt.tm_sec)
        return "%s" % (t)

    def emit(self, record):

        if record.levelname == "ERROR":
            level_prefix = REDB
            message_prefix = REDB
        elif record.levelname == "WARNING":
            level_prefix = ORANGE
            message_prefix = ORANGE
        else:
            level_prefix = YELLOW
            message_prefix = ""

        self.stream.write("%s%s%s - <%s%s%s> -- %s%s%s\n" % (
            GREEN,
            self.formatTime(record),
            RESET,
            level_prefix,
            record.levelname.title(),
            RESET,
            message_prefix,
            self.mask_secrets(record.getMessage()),
            RESET))

    def mask_secrets(self, msg):
        for secret in secrets:
            msg = msg.replace(secret, "<%s>" % secrets[secret])
        return msg
