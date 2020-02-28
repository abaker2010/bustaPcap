#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import sys
import colorama 
from .Totals import Totals
from .PrinterBase import PrinterBase
from colorama import Fore, Back, Style
from application.classes.Collectors.Collector import Collector

class Print(PrinterBase):
    #region Init For Class
    def __init__(self, collection, fqdn, verbose):
        self.collection = collection
        self.fqdnbool = fqdn
        self.verbose = verbose
        return
    #endregion

    #region Print All Both For Dir & Single
    def Print_All(self):
        self.print_header()
        self.print_tcp()
        self.print_ssltls()
        self.print_udp()
        self.print_llc()
        self.print_other_protocols()
        self.print_ips_filtered()
        if self.fqdnbool is True:
            self.print_fqdn()

        if self.verbose:
            self.print_formatted_header("Extended Capture Information", headerColor=Fore.MAGENTA)
            self.print_http_info()
            self.print_http_malformed_headers()
        return
    #endregion

    #region Print Header
    def print_header(self):
        if type(self.collection) is Collector:
            s = "Processed Information : "
            self.print_formatted_header(s, optionaltext=self.collection.get_name())
        else:
            s = "Total Directory Information"
            self.print_formatted_header(s)

        s = "Total Packets :"
        self.print_formatted_header(s, starting="\n", optionaltext=self.collection.packet_count())

        return
    #endregion

    #region Print Http Info
    def print_http_info(self):
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpInfo()) != False:
                s = "HTTP Information :"
                self.print_formatted_sub_header(s)
                httpInfo = self.collection.getHttpInfo()
                for url in httpInfo:
                    s = "URL :"
                    self.print_formatted_body_item(s, optionaltext=url,tabs=2)
                    
                    s = "IP Addresses :"
                    self.print_formatted_body_item(s, optionaltext=httpInfo[url]["IP"], tabs=2)

                    s = "Header Information: Sent"
                    self.print_formatted_sub_header(s, tabs=3)

                    for header in httpInfo[url]["Sent"]:
                        for line in header:
                            print("\t\t\t\t%s : %s" % (line, header[line]))

                    s = "Header Information: Received"
                    self.print_formatted_sub_header(s, tabs=3)

                    for header in httpInfo[url]["Recv"]:
                        for line in header:
                            print("\t\t\t\t%s : %s" % (line, header[line]))

                    s = "Header Information: Data"
                    self.print_formatted_sub_header(s, tabs=3)

                    for header in httpInfo[url]["Data-Text-Line"]:
                        for head in header:
                            print("\t\t\t\t%s" % (head))
                    print("\n\n")
        return
    #endregion

    #region Print Http Malformed Headers
    def print_http_malformed_headers(self):
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpMalformedHeaders()) != False:
                
                print(Fore.LIGHTGREEN_EX + "\t\t[-] " + Fore.LIGHTYELLOW_EX + "HTTP Malformed Headers" + Style.RESET_ALL)
                print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
                headersMalformed = self.collection.getHttpMalformedHeaders()
                for url in headersMalformed:
                    print(Fore.LIGHTGREEN_EX + "\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "URL: " + Fore.LIGHTCYAN_EX + url + Style.RESET_ALL)
                    print(Fore.GREEN + "\t\t\t----------------------" + Style.RESET_ALL)
                    if bool(headersMalformed[url]["login"]) != False:
                        print(Fore.LIGHTGREEN_EX + "\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Log In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL)
                        for pktnum in headersMalformed[url]["login"]:
                            print("\t\t\t\t\tLog In: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["login"][pktnum]))
                    if bool(headersMalformed[url]["job"]) != False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Job In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["job"]:
                            print("\t\t\t\t\tJob: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["job"][pktnum]))
                    if bool(headersMalformed[url]["keepalived"]) != False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Keep Alive In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["keepalived"]:
                            print("\t\t\t\t\tKeep Alive: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["keepalived"][pktnum]))
                    if bool(headersMalformed[url]["submit"]) != False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Submit In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["submit"]:
                            print("\t\t\t\t\tSubmit: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["submit"][pktnum]))
                    if bool(headersMalformed[url]["error"]) != False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Error In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["error"]:
                            print("\t\t\t\t\tError: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["error"][pktnum]))
                    print("\n\n")
        return
    #endregion

    #region Print TCP Information
    def print_tcp(self):
        fp = self.collection.filtered_protocols()
        s = "TCP :"
        self.print_formatted_sub_header(s, optionaltext=sum(fp["TCP"].values()))
        
        self.print_formatted_information_item(self.collection.packet_count(), items=fp["TCP"].items())

        return
    #endregion

    #region Print SSL/TLS Information
    def print_ssltls(self):
        if type(self.collection) is Collector:
            sslTLS = self.collection.ssltls()
        else:
            sslTLS = self.collection.ssltls()

        if bool(sslTLS) is True:
            s = "SSL/TLS Version :"
            self.print_formatted_sub_header(s, optionaltext=sum(sslTLS.values()))
            self.print_formatted_information_item(self.collection.packet_count(), items=sslTLS.items())
        return
    #endregion

    #region Print UDP Information
    def print_udp(self):
        fp = self.collection.filtered_protocols()
        s = "UDP :"
        self.print_formatted_sub_header(s, optionaltext=sum(fp["UDP"].values()))
        self.print_formatted_information_item(self.collection.packet_count(), items=fp["UDP"].items())
        return
    #endregion

    #region Print LLC Information
    def print_llc(self):
        header1 = Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "LLC" + Style.RESET_ALL
        header2 = Fore.GREEN + "\t\t-------------" + Style.RESET_ALL
        fp = self.collection.filtered_protocols()
        if bool(fp["LLC"]) is True:
            print(header1)
            print(header2)
            for t in self.collection.filtered_protocols()["LLC"].keys():
                print("\t\t\t%s -> %s" % (t, fp["LLC"][t]))
                print("\t\t\t{0:.2f}%".format((fp["LLC"][t] / self.collection.packet_count() * 100)))
        return
    #endregion

    #region Print Other Protocols
    def print_other_protocols(self):
        s = "In Depth View (All Protocols)"
        self.print_formatted_sub_header(s)
        fp = self.collection.filtered_protocols()

        self.print_formatted_information_item(self.collection.packet_count(), items=fp["OTHER"].items())
        return
    #endregion

    #region Print IPS Information
    def Print_IPS(self):
        print("\n\t\t[-] IP Addresses")
        print("\t\t-------------")
        for snt in self.collection.ip_addresses_only():
                print("\t\t\t%s" % (snt) )
        return
    #endregion

    #region Print IPS Filtered Information
    def print_ips_filtered(self):
        s = "IP Addresses (Filtered)"
        self.print_formatted_sub_header(s)

        evn = 0
        collected = self.collection.ip_addresses_filtered()
        
        for snt in collected.keys():
            ips = snt.split(" -> ")
            print(Fore.LIGHTYELLOW_EX + "\t\t\t" + ips[0] + Fore.LIGHTGREEN_EX + " -> " + Fore.LIGHTYELLOW_EX + ips[-1] + Fore.LIGHTWHITE_EX + " : " + Fore.CYAN + str(collected[snt]) + Style.RESET_ALL)
            evn += 1
            if (evn % 2) == 0:
                print("\n")
        return
    #endregion

    #region Print FQDN Information
    def print_fqdn(self):
        print(Fore.GREEN + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + " IP Addresses -> FQDN" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            fqdn = sorted(self.collection.fqdn().items())
        else:
            fqdn = sorted(self.collection.Capture_IP_FQDN().items())
            
        for k, v in fqdn:
            print(Fore.LIGHTYELLOW_EX + "\t\t\t" + k + Fore.LIGHTWHITE_EX + " : " + Fore.CYAN + v + Style.RESET_ALL)
        return
    #endregion