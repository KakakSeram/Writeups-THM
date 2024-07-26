# [Brainstorm](https://tryhackme.com/r/room/brainstorm)

![Brainstorm](./images/Brainstorm.png)

[Brainstorm](https://tryhackme.com/r/room/brainstorm) is listed as an medium room. Reverse engineer a chat program and write a script to exploit a Windows machine. An overview of what we’ll be using is listed here:

* Nmap
* FTP

## Task 1 - Deploy Machine and Scan Network

Deploy the machine and scan the network to start enumeration!

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

### Answer the questions below

* Deploy the machine

	![task1-IP](./images/task1-IP.png)

* How many ports are open?
	
	`3`

	![task1-nmap](./images/task1-nmap.png)

	FTP open on port 21, an allow to login anonymous.

## Task 2 - Accessing Files

Let's continue with the enumeration!

### Answer the questions below

* What is the name of the exe file you found?

	`chatserver.exe`

	* Login FTP to as anonymous
	
		```
		ftp anonymous@$IP
		```

		![task2-ftp1](./images/task2-ftp1.png)

	* Show file on directory
	
		```
		dir
		```

		![task2-ftp2](./images/task2-ftp2.png)

		We got error message "229 Entering Extended Passive Mode (|||49354|)". So, we need to disable passive mode, press `ctrl+c` and run `passive`

		![task2-ftp3](./images/task2-ftp3.png)

		We got error message again "150 Opening ASCII mode data connection". So, set ftp to binary mode, run `bin`

		![task2-ftp4](./images/task2-ftp4.png)

		And now we can see file on directory

		![task2-ftp5](./images/task2-ftp5.png)

## Task 3 - Access

After enumeration, you now must have noticed that the service interacting on the strange port is some how related to the files you found! Is there anyway you can exploit that strange service to gain access to the system? 

It is worth using a Python script to try out different payloads to gain access! You can even use the files to locally try the exploit. 

If you've not done buffer overflows before, check [this](https://tryhackme.com/room/bof1) room out!

### Answer the questions below

* Read the description.

	* Download `chatserver.exe` and `essfunc.dll` from FTP server
	
		```
		get chatserver.exe
		get essfunc.dll
		```

		![task2-ftp6](./images/task2-ftp6.png)

* After testing for overflow, by entering a large number of characters, determine the EIP offset.

* Now you know that you can overflow a buffer and potentially control execution, you need to find a function where ASLR/DEP is not enabled. Why not check the DLL file.

* Since this would work, you can try generate some shellcode - use msfvenom to generate shellcode for windows.

* After gaining access, what is the content of the root.txt file?
