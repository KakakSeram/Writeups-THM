# [Overpass 2 - Hacked](https://tryhackme.com/r/room/overpass2hacked)

![Overpass2-Hacked](./images/Overpass2-Hacked.png)

## Task 1 - Forensics - Analyse the PCAP

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

Can you work out how the attacker got in, and hack your way back into Overpass' production server?

Note: Although this room is a walkthrough, it expects familiarity with tools and Linux. I recommend learning basic Wireshark and completing Linux Fundamentals as a bare minimum.

md5sum of PCAP file: 11c3b2e9221865580295bc662c35c6dc

### Answer the questions below

* What was the URL of the page they used to upload a reverse shell?

* What payload did the attacker use to gain access?

* What password did the attacker use to privesc?

* How did the attacker establish persistence?

* Using the fasttrack wordlist, how many of the system passwords were crackable?

## Task 2 - Research - Analyse the code

Now that you've found the code for the backdoor, it's time to analyse it.

### Answer the questions below

* What's the default hash for the backdoor?

* What's the hardcoded salt for the backdoor?

* What was the hash that the attacker used? - go back to the PCAP for this!

* Crack the hash using rockyou and a cracking tool of your choice. What's the password?

## Task 3 - Attack - Get back in!

Now that the incident is investigated, Paradox needs someone to take control of the Overpass production server again.

There's flags on the box that Overpass can't afford to lose by formatting the server!

### Answer the questions below

* The attacker defaced the website. What message did they leave as a heading?

* Using the information you've found previously, hack your way back in!

* What's the user flag?

* What's the root flag?