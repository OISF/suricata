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
                        obj = obj[key]
                    if not obj == md_filter['filter_value']:
                            found = False
                            break
                    if found:
                        md.seen += 1
                except KeyError:
                    pass


parser = argparse.ArgumentParser(prog='suripcap', description='Script checking pcap')

parser.add_argument('-c', '--config', default="suripcap.yaml", dest='config', help='specify configuration file to load')
parser.add_argument('-k', '--keep', action='store_const', const=True, default=False, help='keep generated files in case of test failure')
parser.add_argument('-v', '--verbose', action='store_const', const=True, help='verbose output', default=False)
args = parser.parse_args()
config = args.config

f = open(config)
tests = yaml.safe_load(f)
f.close()

applayerevents = []
mdfilters = []

exit_code = 0

for test in tests:
    for alevent in test['app-layer-events']: 
        applayerevents.append({'name':alevent['name'], 'flow':alevent['flow'], 'tx':alevent['tx']})

    for metadata in test['metadata']:
        md = Metadata(metadata['name'], metadata['event_type'], metadata['count'])
        for filter_str in metadata['filter'].split(' '):
            filter_str = filter_str.split('=', 2)
            key = filter_str[0]
            value = filter_str[1].strip(" ")
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
    if os.path.isfile(ruleset_file):
        print("ruleset_file found")
    else:
        ruleset_file = '/dev/null'
    if os.path.isfile(pcap_file):
        if args.verbose:
            print("pcap_file found")
    else:
        print("pcap_file NOT found")
    tmpdir = mkdtemp()
    cmd = "../src/suricata -c %s -S %s -r %s -l %s %s" % (config_file, ruleset_file, pcap_file, tmpdir, options)
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
            print("WARNING! test '%s' failed" % (md.name))
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
            print("WARNING! TX mismatch")
            exit_code = 1
        if (apl['flow'] == flow):
            if args.verbose:
                print("Flow matched")
        else:
            print("WARNING! Flow mismatch")
            exit_code = 1

if not exit_code == 0:
    if args.keep:
        print("INFO! Log files available in '%s'" % (tmpdir))
    else:
        shutil.rmtree(tmpdir)
else:
    shutil.rmtree(tmpdir)

sys.exit(exit_code)
