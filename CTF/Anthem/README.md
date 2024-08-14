# [Anthem](https://tryhackme.com/r/room/anthem)

![Anthem](./images/Anthem.png)

[Anthem](https://tryhackme.com/r/room/anthem) is listed as an medium room. Exploit a Windows machine in this beginner level challenge. An overview of what we’ll be using is listed here:

* Nmap

## Task 1 - Website Analysis

This task involves you, paying attention to details and finding the 'keys to the castle'.

This room is designed for beginners, however, everyone is welcomed to try it out!

Enjoy the Anthem.

In this room, you don't need to brute force any login page. Just your preferred browser and Remote Desktop.

Please give the box up to 5 minutes to boot and configure.

### Answer the questions below

* Let's run nmap and check what ports are open.

	```
	nmap $IP -A -p- -oN nmap-scan -Pn
	```

	![task1-nmap](./images/task1-nmap.png)

* What port is for the web server?

	**Answer : 80**

* What port is for remote desktop service?

	**Answer : 3389**

* What is a possible password in one of the pages web crawlers check for?

	```
	gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt -o gobuster-scan
	```

	![task1-gobuster](./images/task1-gobuster.png)

	![task1-directory](./images/task1-directory.png)

	Open **robots.txt**

	![task1-robots](./images/task1-robots.png)

	**Answer : UmbracoIsTheBest!**

* What CMS is the website using?

	![task1-umbraco](./images/task1-umbraco.png)
	
	**Answer : Umbraco**

* What is the domain of the website?

	![task1-web](./images/task1-web.png)

	**Answer :  Anthem.com**

* What's the name of the Administrator

	![task1-post](./images/task1-post.png)

	On article **A cheers to our IT department** we found a poem. Search it on google.

	![task1-solomon](./images/task1-solomon.png)

	And we got the username

	**Answer : Solomon Grundy**

* Can we find find the email address of the administrator?
	
	![task1-email](./images/task1-email.png)

	The author is Jane Doe and the email address is JD@anthem.com. Based on this pattern, we can guess Solomon Grundy’s email address. To check that we can try to log in on the CMS with that email address and password we found on the /robots.txt file.

	![task1-login](./images/task1-login.png)

	**Answer : SG@anthem.com**

## Task 2 - Spot the flags

Our beloved admin left some flags behind that we require to gather before we proceed to the next task..

### Answer the questions below

* What is flag 1?

* What is flag 2?

* What is flag 3?

* What is flag 4?

## Task 3 - Final stage

Let's get into the box using the intel we gathered.

### Answer the questions below

* Let's figure out the username and password to log in to the box.(The box is not on a domain)

* Gain initial access to the machine, what is the contents of user.txt?

* Can we spot the admin password?

* Escalate your privileges to root, what is the contents of root.txt?