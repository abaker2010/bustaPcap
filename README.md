# bustaPcap
[![Generic badge](https://img.shields.io/badge/Python-3.7.3-blue.svg)](https://www.python.org/downloads/release/python-373/)
[![Generic badge](https://img.shields.io/badge/build-passing-GREEN.svg)]()
[![Generic badge](https://img.shields.io/badge/version-1.0-GREEN.svg)]()
[![Generic badge](https://img.shields.io/badge/wiki-in_progress-yellow.svg)](https://github.com/abaker2010/bustaPcap/wiki)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/abaker2010/bustaPcap/blob/master/LICENSE)


Creators 
-----------------------
Elliot Kjerstad and Aaron Baker 

Overview
-----------------------

	The program analyzes traffic to help determine protocol usage,
	ssl/tls versions used, IP to IP communication, IP to FQDN, and
	collects HTTP requests, responses, and data. This is a small 
	program that was built for network traffic captures (PCAPS) 
	during the REU internship at DSU.


Requirements
-----------------------
	Pip Requirements : 
	-----------------------
		- colorama	0.4.1
		- configparser 	4.0.2
		- pyshark	0.4.2.3
		- pathlib	1.0.1
		- gnureadline	8.0.0
		- pyreadline 	2.0
	
	* (Recommended) Needed requirements can be installed using the `python3.8 -m pip install -r requirements.txt` command

	Extra Installed Software : 
	-----------------------
		- Tshark
		
	* If you have installed Wireshark this package should be already installed and configured to be used. 


Usage
-----------------------

	python3.8 bustaPcap.py


Future Features
-----------------------

<details close>
<summary>Logging</summary>
<br>
<ul>
<li>[ ] Cleaner log files</li> 
<li>[ ] Option for clearing all log files</li> 
<li>[ ] More options for rebuilding files from the capture</li>
<li>[ ] Improved file structure</li> 
</ul>
 
</details>


<details close>
<summary>Reports</summary>
<br>
<ul>
<li>[ ] Better looking reports</li> 
<li>[ ] Other output options for output files</li>
</ul>
</details>

