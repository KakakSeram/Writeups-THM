# [Retro](https://tryhackme.com/r/room/retro)

![Retro](./images/Retro.png)

[Retro](https://tryhackme.com/r/room/retro) is listed as an medium room. New high score! An overview of what we’ll be using is listed here:

* Nmap

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

	We found open port on 80 and 3389

* Scan directory list with `Gobuster`

	```
	gobuster dir -u  $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -o gobuster-scan
	```

	![gobuster](./images/gobuster.png)

### Answer the questions below

* A web server is running on the target. What is the hidden directory which the website lives on?


* user.txt


* root.txt

