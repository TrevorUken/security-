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
demo commands: 

F12 developers console 





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








