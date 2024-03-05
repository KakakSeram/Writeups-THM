# Agent Sudo

<img src="./images/AgentSudo.png" width="250" height="250">

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
nmap -sV $IP | tee nmap-scan.txt
```

![task2-nmap-scan](./images/task2-nmap-scan.png)

### Scan directory with gobuster



### Answer the questions

* How many open ports?

`3`

* How you redirect yourself to a secret page?



* What is the agent name?

