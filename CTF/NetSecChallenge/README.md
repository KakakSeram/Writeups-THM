# [Net Sec Challenge](https://tryhackme.com/r/room/netsecchallenge)

![NetSecChallenge](./images/NetSecChallenge.png)

[Net Sec Challenge](https://tryhackme.com/r/room/netsecchallenge) is listed as an medium room. Practice the skills you have learned in the Network Security module. An overview of what we’ll be using is listed here:

* Nmap
* Telnet
* Hydra

## Task 1 - Introduction

Use this challenge to test your mastery of the skills you have acquired in the Network Security module. All the questions in this challenge can be solved using only nmap, telnet, and hydra.

### Answer the questions below

* Launch the AttackBox and the target VM.

	![task1-ip](./images/task1-ip.png)


## Task 2 - Challenge Questions

You can answer the following questions using Nmap, Telnet, and Hydra.

### Answer the questions below

* What is the highest port number being open less than 10,000?
	
	`8080`

	```
	nmap -sV $IP -p1-10000 | tee -a nmap-default.txt
	```

	![task2-nmap](./images/task2-nmap.png)

* There is an open port outside the common 1000 ports; it is above 10,000. What is it?

* How many TCP ports are open?

* What is the flag hidden in the HTTP server header?

* What is the flag hidden in the SSH server header?

* We have an FTP server listening on a nonstandard port. What is the version of the FTP server?

* We learned two usernames using social engineering: eddie and quinn. What is the flag hidden in one of these two account files and accessible via FTP?

* Browsing to http://10.10.108.206:8080 displays a small challenge that will give you a flag once you solve it. What is the flag?

## Task 3 - Summary

Congratulations. In this module, we have learned about passive reconnaissance, active reconnaissance, Nmap, protocols and services, and attacking logins with Hydra.
### Answer the questions below

* Time to continue your journey with a new module.