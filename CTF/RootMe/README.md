# RootMe

A CTF for beginners, can you root me?

## Task 1 - Deploy the machine

Set up environment IP as IP_Machine

![task1-IP](./images/task1-IP.png)

## Task 2 - Reconnaissance

* Scan the machine, how many ports are open?
	
	![task2-nmap](./images/task2-nmap.png)

* What version of Apache is running?
	
	![task2-version](./images/task2-version.png)

* What service is running on port 22?
	
	![task2-ssh](./images/task2-ssh.png)

* Find directories on the web server using the GoBuster tool. What is the hidden directory?
	
	![task2-gobuster](./images/task2-gobuster.png)
	

## Task 3 - Getting a shell

* Find a form to upload and get a reverse shell, and find the flag `user.txt`
	
	* Upload reverse shell 
		
		![task4-reverse](./images/task4-reverse.png)

