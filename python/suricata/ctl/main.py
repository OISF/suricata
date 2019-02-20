# Copyright (C) 2018 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

import sys
import os
import argparse
import logging

from suricata.ctl import filestore, loghandler

def init_logger():
    """ Initialize logging, use colour if on a tty. """
    if os.isatty(sys.stderr.fileno()):
        logger = logging.getLogger()
        logger.setLevel(level=logging.INFO)
        logger.addHandler(loghandler.SuriColourLogHandler())
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - <%(levelname)s> - %(message)s")

def main():
    init_logger()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='sub-command help')
    fs_parser = subparsers.add_parser("filestore", help="Filestore related commands")
    filestore.register_args(parser=fs_parser)
    args = parser.parse_args()
    try:
        func = args.func
    except AttributeError:
        parser.error("too few arguments")
    func(args)
