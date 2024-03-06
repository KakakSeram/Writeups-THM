# Agent Sudo

<center><img src="./images/AgentSudo.png" width="250" height="250"></center>

You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.

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

### Download image from machine

![task4-scp](./images/task4-scp.png)

### Answer the questions

* What is the user flag?

	`b03d975e8c92a7c04146cfa7a5a313c7`

* What is the incident of the photo called?

	``