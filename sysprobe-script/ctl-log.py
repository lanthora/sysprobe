#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
import os
import socket
import struct
import sys
import tempfile

client_file = tempfile.NamedTemporaryFile().name
server_file = '/var/run/sysprobectld.sock'

event_type = 2
event_enabled = int(sys.argv[1])
event_ret = -1

unix_domain_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

unix_domain_socket.bind(client_file)
unix_domain_socket.connect(server_file)

bytes_to_send = struct.pack("@Iii", event_type, event_enabled, event_ret)
unix_domain_socket.send(bytes_to_send)
bytes_to_unpack = unix_domain_socket.recv(len(bytes_to_send))

event_type, event_enabled, event_ret = struct.unpack("@Iii", bytes_to_unpack)

print(event_type, event_enabled, event_ret)

os.unlink(client_file)
