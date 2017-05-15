#!/usr/bin/python
# Copyright(C) 2017 Open Information Security Foundation

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

import argparse
import yaml
import os
import json
import sys
from subprocess import Popen, call, check_output, PIPE
from pprint import pprint
from tempfile import mkdtemp
import shutil

BASEPATH = os.path.dirname(os.path.abspath(__file__))

class Metadata:
    def __init__(self, name, event_type, counter):
        self.name = name
        self.event_type = event_type
        self.counter = counter
        self.filters_dict = []
        self.seen = 0

    def addFilter(self, key, value):
        key = key.split('.')
        self.filters_dict.append({'filter_key':key, 'filter_value':value})

    def checkFilters(self, jsline):
        if (jsline[u'event_type'] == self.event_type):
            found = True
            for md_filter in self.filters_dict:
                try:
                    obj=jsline
                    for key in md_filter['filter_key']:
                        try:
                            idx = int(key)
                        except ValueError:
                            idx = key
                        obj = obj[idx]
                    try:
                        value = int(md_filter['filter_value'])
                    except ValueError:
                        value = md_filter['filter_value']
                    if not obj == value:
                        found = False
                        break
                except KeyError:
                    found = False
                    pass
            if found:
                md.seen += 1

parser = argparse.ArgumentParser(prog='suripcap', description='Script checking pcap')

parser.add_argument('-c', '--config', default=os.path.join(BASEPATH, "suripcap.yaml"), dest='config', help='specify configuration file to load')
parser.add_argument('-k', '--keep', action='store_const', const=True, default=False, help='keep generated files in case of test failure')
parser.add_argument('-v', '--verbose', action='store_const', const=True, help='verbose output', default=False)
parser.add_argument('-s', '--suricata', default="../../src/suricata", help='specify path to Suricata binary')
args = parser.parse_args()
config = args.config

f = open(config)
tests = yaml.safe_load(f)
f.close()

exit_code = 0
global_exit = 0

for test in tests:
    applayerevents = []
    mdfilters = []
    if args.verbose:
        print("Running test '%s'" % (test['test']))
    try:
        for alevent in test['app-layer-events']: 
            applayerevents.append({'name':alevent['name'], 'flow':alevent['flow'], 'tx':alevent['tx']})
    except KeyError:
        pass

    if 'metadata' in test.keys():
        for metadata in test['metadata']:
            md = Metadata(metadata['name'], metadata['event_type'], metadata['count'])
            filter_str = metadata['filter'].split('=', 1)
            while len(filter_str) >= 2:
                key = filter_str[0]
                if filter_str[1].startswith("'"):
                    val_split = filter_str[1].split("' ", 1)
                else:
                    val_split = filter_str[1].split(" ", 1)
                value = val_split[0].strip(" ")
                if len(val_split) > 1:
                    filter_str = val_split[1].split('=', 1)
                else:
                    filter_str = []
                if value.startswith("'"):
                    value = value.strip("'")
                elif value == 'false':
                    value = False
                elif value == 'true':
                    value = True
                md.addFilter(key, value)
            mdfilters.append(md)

    name = test['test']
    config_file = test['config']
    ruleset_file = test['ruleset']
    pcap_file = test['filename']
    options = test['options']
    if os.path.isfile(config_file):
        if args.verbose:
            print("config_file found")
    else:
        print("config_file NOT found")
        sys.exit(1)
    if os.path.isfile(ruleset_file):
        if args.verbose:
            print("ruleset_file found")
    else:
        ruleset_file = '/dev/null'
    if os.path.isfile(pcap_file):
        if args.verbose:
            print("pcap_file found")
    else:
        print("pcap_file NOT found")
        sys.exit(1)
    tmpdir = mkdtemp()
    cmd = "%s -c %s -S %s -r %s -l %s %s" % (args.suricata, config_file, ruleset_file, pcap_file, tmpdir, options)
    p = call(cmd.split(), stdout=PIPE)
    with open(os.path.join(tmpdir, 'eve.json')) as data_file:
        for line in data_file:
            jsline = json.loads(line)
            for md in mdfilters:
                md.checkFilters(jsline)
            if (jsline[u'event_type'] == "stats"):
                jsstats = jsline[u'stats'][u'app_layer']

    for md in mdfilters:
        if not md.counter == md.seen:
            print("WARNING! test '%s' failed (expected: %s, seen: %s)" % (md.name, md.counter, md.seen))
            exit_code = 1

    for apl in applayerevents:
        if args.verbose:
            print("Comparing counters for %s" % apl['name'])
        flow = jsstats['flow'][u'%s'%apl['name']]
        tx = jsstats['tx'][u'%s'%apl['name']]
        if (apl['tx'] == tx):
            if args.verbose:
                print("TX matched")
        else:
            print("WARNING! TX mismatch for '%s' in test '%s'" % (apl['name'], test['test']))
            exit_code = 1
        if (apl['flow'] == flow):
            if args.verbose:
                print("Flow matched")
        else:
            print("WARNING! Flow mismatch for '%s' in test '%s'" % (apl['name'], test['test']))
            exit_code = 1

    if not exit_code == 0:
        global_exit = exit_code
        if args.keep:
            print("INFO! Log files available for test '%s' in '%s'" % (test['test'], tmpdir))
        else:
            shutil.rmtree(tmpdir)
    else:
        shutil.rmtree(tmpdir)
    exit_code = 0
    jsstats = None

sys.exit(global_exit)
