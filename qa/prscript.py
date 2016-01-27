#!/usr/bin/env python
# Copyright(C) 2013, 2014, 2015 Open Information Security Foundation

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

# Note to Docker users:
# If you are running SELinux in enforced mode, you may want to run
#   chcon -Rt svirt_sandbox_file_t SURICATA_ROOTSRC_DIR
# or the buildbot will not be able to access to the data in /data/oisf
# and the git step will fail.

import urllib, urllib2, cookielib
try:
    import simplejson as json
except:
    import json
import time
import argparse
import sys
import os
import copy

GOT_NOTIFY = True
try:
    import pynotify
except:
    GOT_NOTIFY = False

GOT_DOCKER = True
try:
    from docker import Client
except:
    GOT_DOCKER = False
# variables
#  - github user
#  - buildbot user and password

BASE_URI="https://buildbot.openinfosecfoundation.org/"
GITHUB_BASE_URI = "https://api.github.com/repos/"
GITHUB_MASTER_URI = "https://api.github.com/repos/inliniac/suricata/commits?sha=master"

if GOT_DOCKER:
    parser = argparse.ArgumentParser(prog='prscript', description='Script checking validity of branch before PR')
else:
    parser = argparse.ArgumentParser(prog='prscript', description='Script checking validity of branch before PR',
                                     epilog='You need to install Python docker module to enable docker container handling options.')
parser.add_argument('-u', '--username', dest='username', help='github and buildbot user')
parser.add_argument('-p', '--password', dest='password', help='buildbot password')
parser.add_argument('-c', '--check', action='store_const', const=True, help='only check last build', default=False)
parser.add_argument('-v', '--verbose', action='store_const', const=True, help='verbose output', default=False)
parser.add_argument('--norebase', action='store_const', const=True, help='do not test if branch is in sync with master', default=False)
parser.add_argument('-r', '--repository', dest='repository', default='suricata', help='name of suricata repository on github')
parser.add_argument('-l', '--local', action='store_const', const=True, help='local testing before github push', default=False)
if GOT_NOTIFY:
    parser.add_argument('-n', '--notify', action='store_const', const=True, help='send desktop notification', default=False)

docker_deps = ""
if not GOT_DOCKER:
    docker_deps = " (disabled)"
parser.add_argument('-d', '--docker', action='store_const', const=True, help='use docker based testing', default=False)
parser.add_argument('-C', '--create', action='store_const', const=True, help='create docker container' + docker_deps, default=False)
parser.add_argument('-s', '--start', action='store_const', const=True, help='start docker container' + docker_deps, default=False)
parser.add_argument('-S', '--stop', action='store_const', const=True, help='stop docker container' + docker_deps, default=False)
parser.add_argument('-R', '--rm', action='store_const', const=True, help='remove docker container and image' + docker_deps, default=False)
parser.add_argument('branch', metavar='branch', help='github branch to build', nargs='?')
args = parser.parse_args()
username = args.username
password = args.password
cookie = None

if args.create or args.start or args.stop:
    if GOT_DOCKER:
        args.docker = True
        args.local = True
    else:
        print "You need to install python docker to use docker handling features."
        sys.exit(-1)

if not args.local:
    if not args.username:
        print "You need to specify a github username (-u option) for this mode (or use -l to disable)"
        sys.exit(-1)

if args.docker:
    BASE_URI="http://localhost:8010/"
    BUILDERS_LIST = ["gcc", "clang", "debug", "features", "profiling", "pcaps"]
else:
    BUILDERS_LIST = [username, username + "-pcap"]

BUILDERS_URI=BASE_URI+"builders/"
JSON_BUILDERS_URI=BASE_URI+"json/builders/"

if GOT_NOTIFY:
    if args.notify:
        pynotify.init("PRscript")

def SendNotification(title, text):
    if not GOT_NOTIFY:
        return
    if not args.notify:
        return
    n = pynotify.Notification(title, text)
    n.show()

def TestRepoSync(branch):
    request = urllib2.Request(GITHUB_MASTER_URI)
    page = urllib2.urlopen(request)
    json_result = json.loads(page.read())
    sha_orig = json_result[0]["sha"]
    request = urllib2.Request(GITHUB_BASE_URI + username + "/" + args.repository + "/commits?sha=" + branch + "&per_page=100")
    page = urllib2.urlopen(request)
    json_result = json.loads(page.read())
    found = -1
    for commit in json_result:
        if commit["sha"] == sha_orig:
            found = 1
            break
    return found

def OpenBuildbotSession():
    auth_params = { 'username':username,'passwd':password, 'name':'login'}
    cookie = cookielib.LWPCookieJar()
    params = urllib.urlencode(auth_params)
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
    urllib2.install_opener(opener)
    request = urllib2.Request(BASE_URI + 'login', params)
    page = urllib2.urlopen(request)
    return cookie


def SubmitBuild(branch, extension = "", builder_name = None):
    raw_params = {'branch':branch,'reason':'Testing ' + branch, 'name':'force_build', 'forcescheduler':'force'}
    params = urllib.urlencode(raw_params)
    if not args.docker:
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
        urllib2.install_opener(opener)
    if builder_name == None:
        builder_name = username + extension
    request = urllib2.Request(BUILDERS_URI + builder_name + '/force', params)
    page = urllib2.urlopen(request)

    result = page.read()
    if args.verbose:
        print "=== response ==="
        print result
        print "=== end of response ==="
    if args.docker:
        if "<h2>Pending Build Requests:</h2>" in result:
            print "Build '" + builder_name + "' submitted"
            return 0
        else:
            return -1
    if "Current Builds" in result:
        print "Build '" + builder_name + "' submitted"
        return 0
    else:
        return -1

# TODO honor the branch argument
def FindBuild(branch, extension = "", builder_name = None):
    if builder_name == None:
        request = urllib2.Request(JSON_BUILDERS_URI + username + extension + '/')
    else:
        request = urllib2.Request(JSON_BUILDERS_URI + builder_name + '/')
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

def GetBuildStatus(builder, buildid, extension="", builder_name = None):
    if builder_name == None:
        builder_name = username + extension
    # https://buildbot.suricata-ids.org/json/builders/build%20deb6/builds/11
    request = urllib2.Request(JSON_BUILDERS_URI + builder_name + '/builds/' + str(buildid))
    page = urllib2.urlopen(request)
    result = page.read()
    if args.verbose:
        print "=== response ==="
        print result
        print "=== end of response ==="
    json_result = json.loads(result)
    if json_result["currentStep"]:
        return 1
    if 'successful' in json_result["text"]:
        return 0
    return -1

def WaitForBuildResult(builder, buildid, extension="", builder_name = None):
    # fetch result every 10 secs till task is over
    if builder_name == None:
        builder_name = username + extension
    res = 1
    while res == 1:
        res = GetBuildStatus(username,buildid, builder_name = builder_name)
        if res == 1:
            time.sleep(10)

    # return the result
    if res == 0:
        print "Build successful for " + builder_name
    else:
        print "Build failure for " + builder_name + ": " + BUILDERS_URI + builder_name + '/builds/' + str(buildid)
    return res

    # check that github branch and inliniac master branch are sync
if not args.local and TestRepoSync(args.branch) == -1:
    if args.norebase:
        print "Branch " + args.branch + " is not in sync with inliniac's master branch. Continuing due to --norebase option."
    else:
        print "Branch " + args.branch + " is not in sync with inliniac's master branch. Rebase needed."
        sys.exit(-1)

def CreateContainer():
    cli = Client()
    # FIXME check if existing
    print "Pulling docking image, first run should take long"
    cli.pull('regit/suri-buildbot')
    cli.create_container(name='suri-buildbot', image='regit/suri-buildbot', ports=[8010, 22], volumes=['/data/oisf', '/data/buildbot/master/master.cfg'])
    sys.exit(0)

def StartContainer():
    cli = Client()
    suri_src_dir = os.path.split(os.path.dirname(os.path.realpath(__file__)))[0]
    print "Using base src dir: " + suri_src_dir
    cli.start('suri-buildbot', port_bindings={8010:8010, 22:None}, binds={suri_src_dir: { 'bind': '/data/oisf', 'ro': True}, os.path.join(suri_src_dir,'qa','docker','buildbot.cfg'): { 'bind': '/data/buildbot/master/master.cfg', 'ro': True}} )
    sys.exit(0)

def StopContainer():
    cli = Client()
    cli.stop('suri-buildbot')
    sys.exit(0)

def RmContainer():
    cli = Client()
    try:
        cli.remove_container('suri-buildbot')
    except:
        print "Unable to remove suri-buildbot container"
        pass
    try:
        cli.remove_image('regit/suri-buildbot:latest')
    except:
        print "Unable to remove suri-buildbot images"
        pass
    sys.exit(0)

if GOT_DOCKER:
    if args.create:
        CreateContainer()
    if args.start:
        StartContainer()
    if args.stop:
        StopContainer()
    if args.rm:
        RmContainer()

if not args.branch:
    print "You need to specify a branch for this mode"
    sys.exit(-1)

# submit buildbot form to build current branch on the devel builder
if not args.check:
    if not args.docker:
        cookie = OpenBuildbotSession()
        if cookie == None:
            print "Unable to connect to buildbot with provided credentials"
            sys.exit(-1)
    for build in BUILDERS_LIST:
        res = SubmitBuild(args.branch, builder_name = build)
        if res == -1:
            print "Unable to start build. Check command line parameters"
            sys.exit(-1)

buildids = {}

if args.docker:
    time.sleep(2)

# get build number and exit if we don't have
for build in BUILDERS_LIST:
    buildid = FindBuild(args.branch, builder_name = build)
    if buildid == -1:
        print "Pending build tracking is not supported. Follow build by browsing " + BUILDERS_URI + build
    elif buildid == -2:
        print "No build found for " + BUILDERS_URI + build
        sys.exit(0)
    else:
        if not args.docker:
            print "You can watch build progress at " + BUILDERS_URI + build + "/builds/" + str(buildid)
        buildids[build] = buildid

if args.docker:
    print "You can watch build progress at " + BASE_URI + "waterfall"

if len(buildids):
    print "Waiting for build completion"
else:
    sys.exit(0)

res = 0
if args.docker:
    while len(buildids):
        up_buildids = copy.copy(buildids)
        for build in buildids:
            ret = GetBuildStatus(build, buildids[build], builder_name = build)
            if ret == -1:
                res = -1
                up_buildids.pop(build, None)
                if len(up_buildids):
                    remains = " (remaining builds: " + ', '.join(up_buildids.keys()) + ")"
                else:
                    remains = ""
                print "Build failure for " + build + ": " + BUILDERS_URI + build + '/builds/' + str(buildids[build]) + remains
            elif ret == 0:
                up_buildids.pop(build, None)
                if len(up_buildids):
                    remains = " (remaining builds: " + ', '.join(up_buildids.keys()) + ")"
                else:
                    remains = ""
                print "Build successful for " + build + remains
        time.sleep(5)
        buildids = up_buildids
    if res == -1:
        SendNotification("PRscript failure", "Some builds have failed. Check <a href='" + BASE_URI + "waterfall'>waterfall</a> for results.")
        sys.exit(-1)
    else:
        print "PRscript completed successfully"
        SendNotification("PRscript success", "Congrats! All builds have passed.")
        sys.exit(0)
else:
    for build in buildids:
        res = WaitForBuildResult(build, buildids[build], builder_name = build)

if res == 0:
    if not args.norebase and not args.docker:
        print "You can copy/paste following lines into github PR"
        for build in buildids:
            print "- PR " + build + ": " + BUILDERS_URI + build + "/builds/" + str(buildids[build])
    SendNotification("OISF PRscript success", "Congrats! All builds have passed.")
    sys.exit(0)
else:
    SendNotification("OISF PRscript failure", "Some builds have failed. Check <a href='" + BASE_URI + "waterfall'>waterfall</a> for results.")
    sys.exit(-1)
