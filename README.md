# bustaPcap
[![Generic badge](https://img.shields.io/badge/Python-3.7.3-blue.svg)](https://www.python.org/downloads/release/python-373/)
[![Generic badge](https://img.shields.io/badge/build-passing-GREEN.svg)]()
[![Generic badge](https://img.shields.io/badge/version-beta_1.0-GREEN.svg)]()
[![Generic badge](https://img.shields.io/badge/wiki-in_progress-yellow.svg)](https://github.com/abaker2010/bustaPcap/wiki)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/abaker2010/bustaPcap/blob/master/LICENSE)


Creators 
-----------------------
Elliot Kjerstad and Aaron Baker 

Overview
-----------------------

	This is a small program that was built for network traffic captures (PCAPS) 
	during the REU internship at DSU. The program analyzes traffic to help 
	determine protocol usage, ssl/tls versions used, IP to IP communication, 
	IP to FQDN, and collects HTTP requests, responses, and data.


Requirements
-----------------------
	Pip Requirements : 
	-----------------------
		- colorama  0.4.1
		- pathlib   1.0.1
		- pyshark   0.4.2.3
	
	* (Recommended) Needed requirements can be installed using the `python3.8 -m pip install -r requirements` command

	Extra Installed Software : 
	-----------------------
		- Tshark
		
	* If you have installed Wireshark this package should be already installed and configured to be used. 


Usage
-----------------------

	python3.8 bustaPcap.py [OPTIONS]


	Example:
	-----------------------
        python3.7 bustaPcap.py -p ./single.pcap -q -o
        python3.7 bustaPcap.py -d ./dir -q True -o
        python3.7 bustaPcap.py -d ./dir -q True -o -q -v


	Command Arguments
	-----------------------
		--version
							show program's version number and exit

		-h, --help
							show this help message and exit

		-d  --DIR=DIR_PATH
							Directory path that holds all PCAP files for parsing.
							Allowed files within are .pcap, .cap, .pcapng

		-p  --PCAP=PCAP_FILE
							PCAP File that will be parsed. Include whole
							destination path: Allowed file types are: .pcap, .cap,
							.pcapng

		-q  --FQDN=DO_FQDN
							Usage: -q <FALSE|true>    This option finds Fully
							Qualified Domain Names with each IP found

		-v, --VERBOSE
							Usage: -v|--VERBOSE   Verbose setting allowing for
							optional printing to screen

		-o  --OUTPUT=SAVE_FILE
							Usage: -o <filename>    This option saves the output
							into the provided filename