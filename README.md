# DSUPCAP

Built with Python 3.7.3
-----------------------
Creators 
-----------------------
Elliot Kjerstad and Aaron Baker 

Overview
-----------------------

	This is a small program that was built for network traffic captures (PCAPS) during the REU internship at DSU.
	The program analyzes traffic to help determine protocol usage, ssl/tls versions used, IP to IP communication, IP to FQDN, 
	and collects HTTP requests, responses, and data.

Usage
-----------------------

	python3.7 PCAP.py


	Command Arguments
	-----------------------
	    -o SAVE_FILE,   This option saves the output
                        into the provided filename this auto saves as a text 
						file so extentions can be omited
						
		-d DIR_PATH,    Directory path that holds all PCAP files for parsing.
                        Allowed files within are .pcap, .cap, .pcapng
						
		-p PCAP_FILE,   PCAP File that will be parsed. Include whole
                        destination path: Allowed file types are: .pcap, .cap,
                        .pcapng

	Pip Requirements
	-----------------------
		- pyshark
