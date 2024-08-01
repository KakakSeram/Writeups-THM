#!/usr/share/python

import socket, time, sys

ip = "10.37.1.149"
port = 9999
timeout = 5

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
s.send(b"AAAA \r\n")

