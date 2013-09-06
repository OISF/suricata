#!/usr/bin/env python
# Copyright(C) 2013 Open Information Security Foundation

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

import urllib, urllib2
import simplejson as json
import time
import argparse
import sys
# variables
#  - github user
#  - buildbot user and password

BASE_URI="https://buildbot.suricata-ids.org/"
BUILDERS_URI=BASE_URI+"builders/"
JSON_BUILDERS_URI=BASE_URI+"json/builders/"

GITHUB_BASE_URI = "https://api.github.com/repos/"
GITHUB_MASTER_URI = "https://api.github.com/repos/inliniac/suricata/commits?sha=master"

parser = argparse.ArgumentParser(prog='prscript', description='Script checking validity of branch before PR')
parser.add_argument('-u', '--username', dest='username', help='github and buildbot user')
parser.add_argument('-p', '--password', dest='password', help='buildbot password')
parser.add_argument('-c', '--check', action='store_const', const=True, help='only check last build', default=False)
parser.add_argument('-r', '--repository', dest='repository', default='suricata', help='suricata repository on github')
parser.add_argument('branch', metavar='branch', help='github branch to build')
args = parser.parse_args()
username = args.username
password = args.password

def TestRepoSync(branch):
    request = urllib2.Request(GITHUB_MASTER_URI)
    page = urllib2.urlopen(request)
    json_result = json.loads(page.read())
    sha_orig = json_result[0]["sha"]
    request = urllib2.Request(GITHUB_BASE_URI + username + "/" + args.repository + "/commits?sha=" + branch)
    page = urllib2.urlopen(request)
    json_result = json.loads(page.read())
    found = -1
    for commit in json_result:
        if commit["sha"] == sha_orig:
            found = 1
            break
    return found



def SubmitBuild(branch):
    raw_params = {'username':username,'passwd':password,'branch':branch,'comments':'Testing ' + branch, 'name':'force_build'}
    params = urllib.urlencode(raw_params)
    request = urllib2.Request(BUILDERS_URI + username + '/force', params)
    page = urllib2.urlopen(request)
    info = page.info()
    result = page.read()
    if "Current Builds" in result:
        print "Build submitted"
        return 0
    else:
        return -1

# TODO honor the branch argument
def FindBuild(branch):
    request = urllib2.Request(JSON_BUILDERS_URI + username + '/')
    page = urllib2.urlopen(request)
    json_result = json.loads(page.read())
    # Pending build is unnumbered
    if json_result["pendingBuilds"]:
        return -1
    if json_result["currentBuilds"]:
        return json_result["currentBuilds"][0]
    if json_result["cachedBuilds"]:
        return json_result["cachedBuilds"][-1]
    return -2

def GetBuildStatus(builder, buildid):
    # https://buildbot.suricata-ids.org/json/builders/build%20deb6/builds/11
    request = urllib2.Request(JSON_BUILDERS_URI + username + '/builds/' + str(buildid))
    page = urllib2.urlopen(request)
    json_result = json.loads(page.read())
    if json_result["currentStep"]:
        return 1
    if 'successful' in json_result["text"]:
        return 0
    return -1

# check that github branch and inliniac master branch are sync
if TestRepoSync(args.branch) == -1:
    print "Branch " + args.branch + " is not in sync with inliniac's master branch. Rebase needed."
    sys.exit(-1)

# submit buildbot form to build current branch on the devel builder
if not args.check:
    res = SubmitBuild(args.branch)
    if res == -1:
        print "Unable to start build. Check command line parameters"
        sys.exit(-1)
    print "Waiting for test completion"

# get build number and exit if we don't have
buildid = FindBuild(args.branch)
if buildid == -1:
    print "Pending build tracking is not supported. Follow build by browsing " + BUILDERS_URI + username
    sys.exit(-1)
if buildid == -2:
    print "No build found for " + BUILDERS_URI + username
    sys.exit(0)
# fetch result every 10 secs till task is over

res = 1
while res == 1:
    res = GetBuildStatus(username,buildid)
    if res == 1:
        time.sleep(10)

# return the result
if res == 0:
    print "Build successful"
    sys.exit(0)
else:
    print "Build failure: " + BUILDERS_URI + username + '/builds/' + str(buildid)
    sys.exit(-1)
