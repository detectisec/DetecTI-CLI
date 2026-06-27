<h6 align="center">Shodan + ExploitDB + GitHub + NVD</h6>
<h1 align="center"><img width="40" src=https://raw.githubusercontent.com/Ls4ss/ThreatTrack/main/example/logo.png>ThreatTrack</h1>

This Python project aims to provide a tool for analyzing the security of IPs and Domains using the Shodan.io API. The script collects information about IPs and Domains, identifies potential vulnerabilities related to the versions of technologies mapped by Shodan, and queries CVEs in the NVD (https://nist.gov) and ExploitDB (https://exploit-db.com) databases. Additionally, it searches for Proof of Concepts (PoCs) of the CVEs on GitHub.

### Features
+ Collection of information about IPs and Domains using the Shodan.io API.
+ Identification of vulnerabilities based on mapped technology versions.
+ Querying of CVEs in the NVD and ExploitDB databases.
+ Simple and easy-to-use interface.

### Help
<img width="700" src=https://raw.githubusercontent.com/Ls4ss/ThreatTrack/main/example/tt_help.png align="center">

### Installation

        git clone https://github.com/detectibr/ThreatTrack.git

        pip3 install -r requirements.txt

        python3 ThreatTrack.py --xdbupdate
        
#### Requirements
        
+ shodan
+ cve_searchsploit
+ ipcalc
+ ipaddress
+ requests
+ argparse
        
##### Get your Shodan API key - https://shodan.io
##### Insert your Shodan API key in API.txt

---

## 🛠️ Creator and Maintainer

<a href="https://github.com/Ls4ss">
  <img src="https://avatars.githubusercontent.com/u/25537761?v=4" width="120px;" style="border-radius: 50%;" alt="Ls4ss Profile"/>
  <br />
  <sub><b>Ls4ss</b></sub>
</a>

Feel free to open Issues or submit Pull Requests to contribute to the project!
