#!/bin/bash
# Copyright(C) 2012 Open Information Security Foundation

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
set -e

SURICATA=suricata

if [ $# -ne 2 ]; then
 	echo "Error: Need two arguments"
	echo "Usage: suric-conf-diff.sh YAML1 YAML2"
	exit 1
fi

TMPDIR=$(mktemp -d)
$SURICATA --dump-config -c $1 | grep -v '<Info>' > $TMPDIR/conf1
$SURICATA --dump-config -c $2 | grep -v '<Info>' > $TMPDIR/conf2

diff -u0 $TMPDIR/conf1 $TMPDIR/conf2

rm $TMPDIR/conf1
rm $TMPDIR/conf2
rmdir $TMPDIR
