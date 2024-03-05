# Agent Sudo

<center><img src="./images/AgentSudo.png" width="250" height="250"></center>

You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.

## Task1 - Author note

Welcome to another THM exclusive CTF room. Your task is simple, capture the flags just like the other CTF room. Have Fun!

```
export IP=10.10.218.33
```

![IP](./images/IP.png)

## Task2 - Enumerate

Enumerate the machine and get all the important information

### Try to open IP from browser

![task2-browser](./images/task2-browser.png)

### Scan open port with nmap

```
nmap -sV -sC -oN nmap-scan $IP
```

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

* Set User-Agent codename as C

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