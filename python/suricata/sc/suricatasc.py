#!/usr/bin/python
# Copyright(C) 2012-2020 Open Information Security Foundation

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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

try:
    import simplejson as json
except ImportError:
    import json
import readline
import select
import sys
from socket import AF_UNIX, error, socket

from suricata.sc.specs import argsd

SURICATASC_VERSION = "1.0"
VERSION = "0.2"
INC_SIZE = 1024


class SuricataException(Exception):
    """
    Generic class for suricatasc exception
    """
    def __init__(self, value):
        super(SuricataException, self).__init__(value)
        self.value = value

    def __str__(self):
        return str(self.value)


class SuricataNetException(SuricataException):
    """
    Exception raised when a network error occurs
    """


class SuricataCommandException(SuricataException):
    """
    Exception raised when the command is incorrect
    """


class SuricataReturnException(SuricataException):
    """
    Exception raised when return message is incorrect
    """


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


class SuricataSC:
    def __init__(self, sck_path, verbose=False):
        self.basic_commands = [
                "shutdown",
                "quit",
                "pcap-file-number",
                "pcap-file-list",
                "pcap-last-processed",
                "pcap-interrupt",
                "iface-list",
                ]
        self.fn_commands = [
                "pcap-file",
                "pcap-file-continuous",
                "iface-stat",
                "conf-get",
                "unregister-tenant-handler",
                "register-tenant-handler",
                "unregister-tenant",
                "register-tenant",
                "reload-tenant",
                "add-hostbit",
                "remove-hostbit",
                "list-hostbit",
                "memcap-set",
                "memcap-show",
                "dataset-add",
                "dataset-remove",
                ]
        self.cmd_list = self.basic_commands + self.fn_commands
        self.sck_path = sck_path
        self.verbose = verbose
        self.socket = socket(AF_UNIX)

    def json_recv(self):
        cmdret = None
        data = ""
        while True:
            if sys.version < '3':
                received = self.socket.recv(INC_SIZE)
            else:
                received = self.socket.recv(INC_SIZE).decode('iso-8859-1')

            if not received:
                break

            data += received
            if data.endswith('\n'):
                cmdret = json.loads(data)
                break
        return cmdret

    def send_command(self, command, arguments=None):
        if command not in self.cmd_list and command != 'command-list':
            raise SuricataCommandException("Command not found: {}".format(command))

        cmdmsg = {}
        cmdmsg['command'] = command
        if arguments:
            cmdmsg['arguments'] = arguments
        if self.verbose:
            print("SND: " + json.dumps(cmdmsg))
        cmdmsg_str = json.dumps(cmdmsg) + "\n"
        if sys.version < '3':
            self.socket.send(cmdmsg_str)
        else:
            self.socket.send(bytes(cmdmsg_str, 'iso-8859-1'))

        ready = select.select([self.socket], [], [], 600)
        if ready[0]:
            cmdret = self.json_recv()
        else:
            cmdret = None
        if not cmdret:
            raise SuricataReturnException("Unable to get message from server")

        if self.verbose:
            print("RCV: "+ json.dumps(cmdret))

        return cmdret

    def connect(self):
        try:
            if self.socket is None:
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

        if not cmdret:
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
        self.socket = None

    def execute(self, command):
        full_cmd = command.split()
        cmd = full_cmd[0]
        cmd_specs = argsd[cmd]
        required_args_count = len([d["required"] for d in cmd_specs if d["required"] and not "val" in d])
        arguments = dict()
        for c, spec in enumerate(cmd_specs, 1):
            spec_type = str if "type" not in spec else spec["type"]
            if spec["required"]:
                if spec.get("val"):
                    arguments[spec["name"]] = spec_type(spec["val"])
                    continue
                try:
                    arguments[spec["name"]] = spec_type(full_cmd[c])
                except IndexError:
                    phrase = " at least" if required_args_count != len(cmd_specs) else ""
                    msg = "Missing arguments: expected{} {}".format(phrase, required_args_count)
                    raise SuricataCommandException(msg)
                except ValueError as ve:
                    raise SuricataCommandException("Erroneous arguments: {}".format(ve))
            elif c < len(full_cmd):
                arguments[spec["name"]] = spec_type(full_cmd[c])
        return cmd, arguments

    def parse_command(self, command):
        arguments = None
        cmd = command.split()[0] if command else None
        if cmd in self.cmd_list:
            if cmd in self.fn_commands:
                cmd, arguments = getattr(self, "execute")(command=command)
        else:
            raise SuricataCommandException("Unknown command {}".format(command))
        return cmd, arguments

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
                    break
                try:
                    cmd, arguments = self.parse_command(command)
                except SuricataCommandException as err:
                    print(err)
                    continue
                try:
                    cmdret = self.send_command(cmd, arguments)
                except IOError as err:
                    # try to reconnect and resend command
                    print("Connection lost, trying to reconnect")
                    try:
                        self.close()
                        self.connect()
                    except SuricataNetException as err:
                        print("Can't reconnect to suricata socket, discarding command")
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
