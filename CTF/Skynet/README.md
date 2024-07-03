# [Skynet](https://tryhackme.com/r/room/skynet)

![Skynet](./images/Skynet.png)

[Skynet](https://tryhackme.com/r/room/skynet) is listed as an easy room. A vulnerable Terminator themed Linux machine. An overview of what we’ll be using is listed here:

* Nmap
* Gobuster
* enum4linux
* Hydra
* Searchsploit

[IP](./images/IP.png)

## Task 1 - Deploy and compromise the vulnerable machine!

![logo](./images/logo.png)

Are you able to compromise this Terminator themed machine?

![blog](./images/blog.png)

You can follow our official walkthrough for this challenge on [our blog](https://blog.tryhackme.com/skynet-writeup/).

## Enumeration

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

* Download `searchsploit` file

	```
	searchsploit -m 25971
	```

	![download](./images/download.png)

### Answer the questions below

* What is Miles password for his emails?

* What is the hidden directory?

* What is the vulnerability called when you can include a remote file for malicious purposes?

* What is the user flag?

* What is the root flag?


