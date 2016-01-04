#!/usr/bin/python
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

try:
    import simplejson as json
except:
    import json
import re
import readline
from socket import socket, AF_UNIX, error
from time import sleep
import select
import sys

SURICATASC_VERSION = "0.9"

VERSION = "0.1"
SIZE = 4096

class SuricataException(Exception):
    """
    Generic class for suricatasc exception
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class SuricataNetException(SuricataException):
    """
    Exception raised when network error occur.
    """
    pass

class SuricataCommandException(SuricataException):
    """
    Exception raised when command is not correct.
    """
    pass

class SuricataReturnException(SuricataException):
    """
    Exception raised when return message is not correct.
    """
    pass


class SuricataCompleter:
    def __init__(self, words):
        self.words = words
        self.generator = None

    def complete(self, text):
        for word in self.words:
            if word.startswith(text):
                yield word

    def __call__(self, text, state):
        if state == 0:
            self.generator = self.complete(text)
        try:
            return next(self.generator)
        except StopIteration:
            return None
        return None

class SuricataSC:
    def __init__(self, sck_path, verbose=False):
        self.cmd_list=['shutdown','quit','pcap-file','pcap-file-number','pcap-file-list','iface-list','iface-stat','register-tenant','unregister-tenant','register-tenant-handler','unregister-tenant-handler']
        self.sck_path = sck_path
        self.verbose = verbose

    def json_recv(self):
        cmdret = None
        i = 0
        data = ""
        while i < 5:
            i += 1
            if sys.version < '3':
                data += self.socket.recv(SIZE)
            else:
                data += self.socket.recv(SIZE).decode('iso-8859-1')
            try:
                cmdret = json.loads(data)
                break
            except:
                sleep(0.3)
        return cmdret

    def send_command(self, command, arguments = None):
        if command not in self.cmd_list and command != 'command-list':
            raise SuricataCommandException("No such command: %s", command)

        cmdmsg = {}
        cmdmsg['command'] = command
        if (arguments != None):
            cmdmsg['arguments'] = arguments
        if self.verbose:
            print("SND: " + json.dumps(cmdmsg))
        if sys.version < '3':
            self.socket.send(json.dumps(cmdmsg))
        else:
            self.socket.send(bytes(json.dumps(cmdmsg), 'iso-8859-1'))

        ready = select.select([self.socket], [], [], 600)
        if ready[0]:
            cmdret = self.json_recv()
        else:
            cmdret = None

        if cmdret == None:
            raise SuricataReturnException("Unable to get message from server")

        if self.verbose:
            print("RCV: "+ json.dumps(cmdret))

        return cmdret

    def connect(self):
        try:
            self.socket = socket(AF_UNIX)
            self.socket.connect(self.sck_path)
        except error as err:
            raise SuricataNetException(err)

        self.socket.settimeout(10)
        #send version
        if self.verbose:
            print("SND: " + json.dumps({"version": VERSION}))
        if sys.version < '3':
            self.socket.send(json.dumps({"version": VERSION}))
        else:
            self.socket.send(bytes(json.dumps({"version": VERSION}), 'iso-8859-1'))

        ready = select.select([self.socket], [], [], 600)
        if ready[0]:
            cmdret = self.json_recv()
        else:
            cmdret = None

        if cmdret == None:
            raise SuricataReturnException("Unable to get message from server")

        if self.verbose:
            print("RCV: "+ json.dumps(cmdret))

        if cmdret["return"] == "NOK":
            raise SuricataReturnException("Error: %s" % (cmdret["message"]))

        cmdret = self.send_command("command-list")

        # we silently ignore NOK as this means server is old
        if cmdret["return"] == "OK":
            self.cmd_list = cmdret["message"]["commands"]
            self.cmd_list.append("quit")


    def close(self):
        self.socket.close()

    def parse_command(self, command):
        arguments = None
        if command.split(' ', 2)[0] in self.cmd_list:
            if "pcap-file " in command:
                try:
                    parts = command.split(' ');
                except:
                    raise SuricataCommandException("Arguments to command '%s' is missing" % (command))
                cmd, filename, output = parts[0], parts[1], parts[2]
                tenant = None
                if len(parts) > 3:
                    tenant = parts[3]
                if cmd != "pcap-file":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["filename"] = filename
                    arguments["output-dir"] = output
                    if tenant != None:
                        arguments["tenant"] = int(tenant)
            elif "iface-stat" in command:
                try:
                    [cmd, iface] = command.split(' ', 1)
                except:
                    raise SuricataCommandException("Unable to split command '%s'" % (command))
                if cmd != "iface-stat":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["iface"] = iface
            elif "conf-get" in command:
                try:
                    [cmd, variable] = command.split(' ', 1)
                except:
                    raise SuricataCommandException("Unable to split command '%s'" % (command))
                if cmd != "conf-get":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["variable"] = variable
            elif "unregister-tenant-handler" in command:
                try:
                    parts = command.split(' ')
                except:
                    raise SuricataCommandException("Arguments to command '%s' is missing" % (command))
                cmd, tenantid, htype = parts[0], parts[1], parts[2]
                hargs = None
                if len(parts) > 3:
                    hargs = parts[3]
                if cmd != "unregister-tenant-handler":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["id"] = int(tenantid)
                    arguments["htype"] = htype
                    if hargs != None:
                        arguments["hargs"] = int(hargs)
            elif "register-tenant-handler" in command:
                try:
                    parts = command.split(' ')
                except:
                    raise SuricataCommandException("Arguments to command '%s' is missing" % (command))
                cmd, tenantid, htype = parts[0], parts[1], parts[2]
                hargs = None
                if len(parts) > 3:
                    hargs = parts[3]
                if cmd != "register-tenant-handler":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["id"] = int(tenantid)
                    arguments["htype"] = htype
                    if hargs != None:
                        arguments["hargs"] = int(hargs)
            elif "unregister-tenant" in command:
                try:
                    [cmd, tenantid] = command.split(' ', 1)
                except:
                    raise SuricataCommandException("Unable to split command '%s'" % (command))
                if cmd != "unregister-tenant":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["id"] = int(tenantid)
            elif "register-tenant" in command:
                try:
                    [cmd, tenantid, filename] = command.split(' ', 2)
                except:
                    raise SuricataCommandException("Arguments to command '%s' is missing" % (command))
                if cmd != "register-tenant":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["id"] = int(tenantid)
                    arguments["filename"] = filename
            elif "reload-tenant" in command:
                try:
                    [cmd, tenantid, filename] = command.split(' ', 2)
                except:
                    raise SuricataCommandException("Arguments to command '%s' is missing" % (command))
                if cmd != "reload-tenant":
                    raise SuricataCommandException("Invalid command '%s'" % (command))
                else:
                    arguments = {}
                    arguments["id"] = int(tenantid)
                    arguments["filename"] = filename
            else:
                cmd = command
        else:
            raise SuricataCommandException("Unknown command '%s'" % (command))
        return (cmd, arguments)

    def interactive(self):
        print("Command list: " + ", ".join(self.cmd_list))
        try:
            readline.set_completer(SuricataCompleter(self.cmd_list))
            readline.set_completer_delims(";")
            readline.parse_and_bind('tab: complete')
            while True:
                if sys.version < '3':
                    command = raw_input(">>> ").strip()
                else:
                    command = input(">>> ").strip()
                if command == "quit":
                    break;
                try:
                    (cmd, arguments) = self.parse_command(command)
                except SuricataCommandException as err:
                    print(err)
                    continue
                cmdret = self.send_command(cmd, arguments)
                #decode json message
                if cmdret["return"] == "NOK":
                    print("Error:")
                    print(json.dumps(cmdret["message"], sort_keys=True, indent=4, separators=(',', ': ')))
                else:
                    print("Success:")
                    print(json.dumps(cmdret["message"], sort_keys=True, indent=4, separators=(',', ': ')))
        except KeyboardInterrupt:
            print("[!] Interrupted")
