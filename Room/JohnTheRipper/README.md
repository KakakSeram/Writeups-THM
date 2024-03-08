# [John The Ripper](https://tryhackme.com/room/johntheripper0)

![JohnTheRipper](./images/JohnTheRipper.png)

## Task 1 - John who?

### Welcome

John the Ripper is one of the most well known, well-loved and versatile hash cracking tools out there. It combines a fast cracking speed, with an extraordinary range of compatible hash types. This room will assume no previous knowledge, so we must first cover some basic terms and concepts before we move into practical hash cracking. 

### What are Hashes?

A hash is a way of taking a piece of data of any length and  representing it in another form that is a fixed length. This masks the original value of the data. This is done by running the original data through a hashing algorithm. There are many popular hashing algorithms, such as MD4,MD5, SHA1 and NTLM. Lets try and show this with an example:

If we take "polo", a string of 4 characters- and run it through an MD5 hashing algorithm, we end up with an output of: b53759f3ce692de7aff1b5779d3964da a standard 32 character MD5 hash.

Likewise, if we take "polomints", a string of 9 characters- and run it through the same MD5 hashing algorithm, we end up with an output of: 584b6e4f4586e136bc280f27f9c64f3b another standard 32 character MD5 hash. 

### What makes Hashes secure?

Hashing algorithms are designed so that they only operate one way. This means that a calculated hash cannot be reversed using just the output given. This ties back to a fundamental mathematical problem known as the [P vs NP relationship](https://en.wikipedia.org/wiki/P_versus_NP_problem).

While this is an extremely interesting mathematical concept that proves fundamental to computing and cryptography I am in no way qualified to try and explain it in detail here; but abstractly it means that the algorithm to hash the value will be "NP" and can therefore be calculated reasonably. However an un-hashing algorithm would be "P" and intractable to solve- meaning that it cannot be computed in a reasonable time using standard computers. 

### Where John Comes in...

Even though the algorithm itself is not feasibly reversible. That doesn't mean that cracking the hashes is impossible. If you have the hashed version of a password, for example- and you know the hashing algorithm- you can use that hashing algorithm to hash a large number of words, called a dictionary. You can then compare these hashes to the one you're trying to crack, to see if any of them match. If they do, you now know what word corresponds to that hash- you've cracked it!

This process is called a **dictionary attack** and John the Ripper, or John as it's commonly shortened to, is a tool to allow you to conduct fast brute force attacks on a large array of different hash types.

### Learning More

For some more in-depth material on specific hashing and Encryption methods I'd recommend checking out NinjaJc01's amazing room covering these topics: [encryptioncrypto101](https://tryhackme.com/room/encryptioncrypto101)

### Answer the questions

`Read and understand the basic concepts of hashing and hash cracking`

## Task 2 - Setting up John the Ripper

### Setting Up John The Ripper

John the Ripper is supported on many different Operating Systems, not just Linux Distributions. As a note before we go through this, there are multiple versions of John, the standard "core" distribution, as well as multiple community editions- which extend the feature set of the original John distribution. The most popular of these distributions is the "Jumbo John"- which we will be using specific features of later.

### Parrot, Kali and AttackBox

If you're using Parrot OS, Kali Linux or TryHackMe's own AttackBox- you should already have Jumbo John installed. You can double check this by typing `john` into the terminal. You should be met with a usage guide for john, with the first line reading: "John the Ripper 1.9.0-jumbo-1" or similar with a different version number. If not, you can use `sudo apt install` john to install it. 

### Blackarch

If you're using Blackarch, or the Blackarch repositories you may or may not have Jumbo John installed, to check if you do, use the command `pacman -Qe | grep "john"` You should be met with an output similar to "john 1.9.0.jumbo1-5" or similar with a different version number. If you do not have it installed, you can simply use `pacman -S john` to install it.

### Building from Source for Linux

If you wish to build the package from source to meet your system requirements, you can do this in five fairly straightforward steps. Further advice on the installation process and how to configure your build from source can be found here.

1. Use `git clone https://github.com/openwall/john -b bleeding-jumbo john` to clone the jumbo john repository to your current working
2. Then `cd john/src/` to change your current directory to where the source code is. 
3. Once you're in this directory, use `./configure` to check the required dependencies and options that have been configured.
4. If you're happy with this output, and have installed any required dependencies that are needed, use `make -s clean && make -sj4` to build a binary of john. This binary will be in the above run directory, which you can change to with `cd ../run`
5. You can test this binary using ./john --test

### Installing on Windows

To install Jumbo John the Ripper on Windows, you just need to download and install the zipped binary for either 64 bit systems [here](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip) or for 32 bit systems [here](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win32.zip).

### Answer the questions

What is the most popular extended version of John the Ripper?

`Jumbo John`

## Task 3 - Wordlists

### Wordlists

As we explained in the first task, in order to dictionary attack hashes, you need a list of words that you can hash and compare, unsurprisingly this is called a wordlist. There are many different wordlists out there, a good collection to use can be found in the [SecLists](https://github.com/danielmiessler/SecLists) repository. There are a few places you can look for wordlists on your attacking system of choice, we will quickly run through where you can find them. 

### Parrot, Kali and AttackBox

On Parrot, Kali and TryHackMe's AttackBox- you can find a series of amazing wordlists in the `/usr/share/wordlists` directory.

### RockYou

For all of the tasks in this room, we will be using the infamous rockyou.txt wordlist- which is a very large common password wordlist, obtained from a data breach on a website called rockyou.com in 2009. If you are not using any of the above distributions, you can get the rockyou.txt wordlist from the SecLists repository under the `/Passwords/Leaked-Databases` subsection. You may need to extract it from .tar.gz format, using `tar xvzf rockyou.txt.tar.gz`.

Now that we have our hash cracker and wordlists all set up, lets move onto some hash cracking!

### Answer the questions

What website was the rockyou.txt wordlist created from a breach on?

`rockyou.com`

## Task 4 - Cracking Basic Hashes

[Downnload Task Files](./files/firsttaskhashes.zip)

### Cracking Basic Hashes

There are multiple ways to use John the Ripper to crack simple hashes, we're going to walk through a few, before moving on to cracking some ourselves. 

### John Basic Syntax

The basic syntax of John the Ripper commands is as follows. We will cover the specific options and modifiers used as we use them.

`john [options] [path to file]`

`john` - Invokes the John the Ripper program

`[path to file]` - The file containing the hash you're trying to crack, if it's in the same directory you won't need to name a path, just the file.

### Automatic Cracking

John has built-in features to detect what type of hash it's being given, and to select appropriate rules and formats to crack it for you, this isn't always the best idea as it can be unreliable- but if you can't identify what hash type you're working with and just want to try cracking it, it can be a good option! To do this we use the following syntax:

`john --wordlist=[path to wordlist] [path to file]`

`--wordlist=` - Specifies using wordlist mode, reading from the file that you supply in the following path...

`[path to wordlist]` - The path to the wordlist you're using, as described in the previous task.

**Example Usage:**

`john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt`

### Identifying Hashes

Sometimes John won't play nicely with automatically recognising and loading hashes, that's okay! We're able to use other tools to identify the hash, and then set john to use a specific format. There are multiple ways to do this, such as using an online hash identifier like this one. I like to use a tool called hash-identifier, a Python tool that is super easy to use and will tell you what different types of hashes the one you enter is likely to be, giving you more options if the first one fails. 

To use hash-identifier, you can just pull the python file from gitlab using:  
`wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py`.

Then simply launch it with `python3 hash-id.py` and then enter the hash you're trying to identify- and it will give you possible formats!

### Format-Specific Cracking

Once you have identified the hash that you're dealing with, you can tell john to use it while cracking the provided hash using the following syntax:

`john --format=[format] --wordlist=[path to wordlist] [path to file]`

`--format=` - This is the flag to tell John that you're giving it a hash of a specific format, and to use the following format to crack it

`[format]` - The format that the hash is in

**Example Usage:**

`john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt`

**A Note on Formats:**

When you are telling john to use formats, if you're dealing with a standard hash type, e.g. md5 as in the example above, you have to prefix it with raw- to tell john you're just dealing with a standard hash type, though this doesn't always apply. To check if you need to add the prefix or not, you can list all of John's formats using john --list=formats and either check manually, or grep for your hash type using something like john --list=formats | grep -iF "md5".

### Practical

Now you know the syntax, modifiers and methods to crack basic hashes, try it yourself! Download the attached .txt files that 

### Answer the questions

* What type of hash is hash1.txt?

	![task4-hash1](./images/task4-hash1.png)

	`MD5`


* What is the cracked value of hash1.txt?

	![task4-hash1crack](./images/task4-hash1crack.png)

	`biscuit`

* What type of hash is hash2.txt?

	![task4-hash2](./images/task4-hash2.png)

	`SHA1`

* What is the cracked value of hash2.txt

	![task4-hash2crack](./images/task4-hash2crack.png)

	`kangeroo`

* What type of hash is hash3.txt?

	![task4-hash3](./images/task4-hash3.png)

	`SHA256`

* What is the cracked value of hash3.txt

	![task4-hash3crack](./images/task4-hash3crack.png)

	`microphone`

* What type of hash is hash4.txt?

	![task4-hash4](./images/task4-hash4.png)

	`Whirlpool`

* What is the cracked value of hash4.txt

	![task4-hash4crack](./images/task4-hash4crack.png)

	`colossal`

## Task 5 - Cracking Windows Authentication Hashes

## Task 6 - Cracking /etc/shadow Hashes

## Task 7 - Single Crack Mode

## Task 8 - Custom Rules

## Task 9 - Cracking Password Protected Zip Files

## Task 10 - Cracking Password Protected RAR Archives

## Task 11 - Cracking SSH Keys with John

## Task 12 - Further Reading

