# [Daily Bugle](https://tryhackme.com/r/room/dailybugle)

![DailyBugle](./images/DailyBugle.png)

[Daily Bugle](https://tryhackme.com/r/room/dailybugle) is listed as an Hard room. Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum. An overview of what we’ll be using is listed here:

* Nmap
* Gobuster

![IP](./images/IP.png)

## Task 1 - Deploy

![task1-logo](./images/task1-logo.png)

Deploy the machine - it may take up to 2 minutes to configure

### Answer the questions below

* Access the web server, who robbed the bank?

	`spiderman`

	![task1-spiderman](./images/task1-spiderman.png)

## Task 2 - Obtain user and root

![task2-logo](./images/task2-logo.png)

Hack into the machine and obtain the root user's credentials.

### Enumeration & Exploit

* Scan open port with **Nmap**

	```
	nmap $IP --script vuln -oN nmap-vuln
	```

	```
	# Nmap 7.94SVN scan initiated Thu Jul  4 04:18:15 2024 as: nmap --script vuln -oN nmap-vuln 10.10.131.171
	Nmap scan report for 10.10.131.171
	Host is up (0.36s latency).
	Not shown: 997 closed tcp ports (conn-refused)
	PORT     STATE SERVICE
	22/tcp   open  ssh
	80/tcp   open  http
	|_http-trace: TRACE is enabled
	| http-csrf: 
	| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.131.171
	|   Found the following possible CSRF vulnerabilities: 
	|     
	|     Path: http://10.10.131.171:80/
	|     Form id: login-form
	|     Form action: /index.php
	|     
	|     Path: http://10.10.131.171:80/index.php/component/users/?view=remind&amp;Itemid=101
	|     Form id: user-registration
	|     Form action: /index.php/component/users/?task=remind.remind&Itemid=101
	|     
	|     Path: http://10.10.131.171:80/index.php/component/users/?view=remind&amp;Itemid=101
	|     Form id: login-form
	|     Form action: /index.php/component/users/?Itemid=101
	|     
	|     Path: http://10.10.131.171:80/index.php/component/users/?view=reset&amp;Itemid=101
	|     Form id: user-registration
	|     Form action: /index.php/component/users/?task=reset.request&Itemid=101
	|     
	|     Path: http://10.10.131.171:80/index.php/component/users/?view=reset&amp;Itemid=101
	|     Form id: login-form
	|     Form action: /index.php/component/users/?Itemid=101
	|     
	|     Path: http://10.10.131.171:80/index.php/2-uncategorised/1-spider-man-robs-bank
	|     Form id: login-form
	|     Form action: /index.php
	|     
	|     Path: http://10.10.131.171:80/index.php
	|     Form id: login-form
	|_    Form action: /index.php
	|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
	| http-vuln-cve2017-8917: 
	|   VULNERABLE:
	|   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
	|     State: VULNERABLE
	|     IDs:  CVE:CVE-2017-8917
	|     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
	|       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
	|       to execute aribitrary SQL commands via unspecified vectors.
	|       
	|     Disclosure date: 2017-05-17
	|     Extra information:
	|       User: root@localhost
	|     References:
	|       https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
	|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917
	| http-dombased-xss: 
	| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.131.171
	|   Found the following indications of potential DOM based XSS: 
	|     
	|     Source: window.open(this.href,'win2','status=no,toolbar=no,scrollbars=yes,titlebar=no,menubar=no,resizable=yes,width=640,height=480,directories=no,location=no')
	|_    Pages: http://10.10.131.171:80/, http://10.10.131.171:80/index.php/2-uncategorised/1-spider-man-robs-bank, http://10.10.131.171:80/index.php
	| http-enum: 
	|   /administrator/: Possible admin folder
	|   /administrator/index.php: Possible admin folder
	|   /robots.txt: Robots file
	|   /administrator/manifests/files/joomla.xml: Joomla version 3.7.0
	|   /language/en-GB/en-GB.xml: Joomla version 3.7.0
	|   /htaccess.txt: Joomla!
	|   /README.txt: Interesting, a readme.
	|   /bin/: Potentially interesting folder
	|   /cache/: Potentially interesting folder
	|   /icons/: Potentially interesting folder w/ directory listing
	|   /images/: Potentially interesting folder
	|   /includes/: Potentially interesting folder
	|   /libraries/: Potentially interesting folder
	|   /modules/: Potentially interesting folder
	|   /templates/: Potentially interesting folder
	|_  /tmp/: Potentially interesting folder
	3306/tcp open  mysql
	```

* Directory scan with **Gobuster**

	```
	gobuster dir -u $IP -w /usr/share/wordlists/dirb/big.txt -t50 | tee gobuster-scan
	```

	![task1-gobuster](./images/task1-gobuster.png)

* Searchsploit by CVE-2017-8917

	```
	searchsploit --cve CVE-2017-8917
	```

	![task1-cve](./images/task1-cve.png)

* Download and read file exsploit

	![task1-exploit](./images/task1-exploit.png)

* Download `joomblah.py`
	
	```
	wget https://raw.githubusercontent.com/XiphosResearch/exploits/master/Joomblah/joomblah.py
	```

	![task1-joomblah](./images/task1-joomblah.png)

### Answer the questions below

* What is the Joomla version?

	`3.7.0`

	![task1-version](./images/task1-version.png)

*Instead of using SQLMap, why not use a python script!*

* What is Jonah's cracked password?

* What is the user flag?

* What is the root flag?

## Task 3 - Credits

![task3-logo](./images/task3-logo.png)

This room uses artwork that is owned by Sony Pictures

### Answer the questions below

* Found another way to compromise the machine or want to assist others in rooting it? Keep an eye on the forum post located [here](https://tryhackme.com/thread/5e1ef29a2eda9b0f20b151fd).