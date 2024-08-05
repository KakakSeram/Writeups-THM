# [Mr Robot CTF](https://tryhackme.com/r/room/mrrobot)

![MrRobotCTF](./images/MrRobotCTF.png) 

[Mr Robot CTF](https://tryhackme.com/r/room/mrrobot) is listed as an medium room. Based on the Mr. Robot show, can you root this box? An overview of what we’ll be using is listed here:

* Nmap
* Gobuster

## Task 1 - Connect to our network

To deploy the Mr. Robot virtual machine, you will first need to connect to our network.

### Answer the questions below

* Connect to our network using OpenVPN. Here is a mini walkthrough of connecting:

	Go to your [access](http://tryhackme.com/access) page and download your configuration file.
	
	![task1-vpn](./images/task1-vpn.png)

* Use an OpenVPN client to connect. In my example I am on Linux, on the access page we have a windows tutorial.

	![task1-ovpn](./images/task1-ovpn) (change "ben.ovpn" to your config file)
	
	When you run this you see lots of text, at the end it will say Initialization Sequence Completed

	You can verify you are connected by looking on your access page. Refresh the page
	
	You should see a green tick next to Connected. It will also show you your internal IP address.
	
	![task1-network](./images/task1-network.png)

* You are now ready to use our machines on our network!

* Now when you deploy material, you will see an internal IP address of your Virtual Machine.

## Task 2 - Hack the machine

<img src="./images/task2-logo.png" height=300  width=auto>

Can you root this Mr. Robot styled machine? This is a virtual machine meant for beginners/intermediate users. There are 3 hidden keys located on the machine, can you find them?

Credit to [Leon Johnson](https://twitter.com/@sho_luv) for creating this machine. **This machine is used here with the explicit permission of the creator <3** 

### Enumeration & Exploitation

* Scan open port with `nmap`

	```
	nmap $IP -A -p- -oN nmap-scan -Pn
	```

	![task2-nmap](./images/task2-nmap.png)

	We got open port on 80 (http) and 443 (htpps). All scan result [here.](./files/nmap-scan)

* Scan directory list with `Gobuster`

	![task2-gobuster](./images/task2-gobuster.png)

	![task2-200](./images/task2-200.png)

	All scan result [here.](./files/gobuster-scan)

### Answer the questions below

* What is key 1?

	Open **/robot** directory
	
	![task2-robots](./images/task2-robots.png)

	We found **key1**

	![task2-key1](./images/task2-key1.png)
	
	**Answer : 073403c8a58a1f80d943455fb30724b9**

* What is key 2?

* What is key 3?