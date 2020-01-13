#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import sys
from classes.Collector import Collector
from classes.Totals import Totals
import colorama 
from colorama import Fore, Back, Style

class Print:
    #region Init For Class
    def __init__(self, collection, fqdn):
        self.collection = collection
        self.fqdnbool = fqdn
        return
    #endregion

    #region Print All Both For Dir & Single
    def Print_All(self):
        if type(self.collection) is Totals:
            for pkt in self.collection.All_Collected():
                Print(pkt, self.fqdnbool).Print_All()
            Print(self.collection, self.fqdnbool).Print_Dir()
        else:
            self.Print_Header()
            self.Print_TCP()
            self.Print_SSLTLS()
            self.Print_UDP()
            self.Print_LLC()
            self.Print_Other_Protocols()
            self.Print_IPS_Filtered()
            if self.fqdnbool is True:
                self.Print_FQDN()
            self.Print_HttpInfo()
            self.Print_HttpMalformedHeaders()
        return
    #endregion

    #region Print Dir Only
    def Print_Dir(self):
        self.Print_Header()
        self.Print_TCP()
        self.Print_SSLTLS()
        self.Print_UDP()
        self.Print_LLC()
        self.Print_Other_Protocols()
        self.Print_IPS_Filtered()
        if self.fqdnbool is True:
            self.Print_FQDN()
        #self.Print_HttpInfo()
        #self.Print_HttpMalformedHeaders()
        return
    #endregion

    #region Print Header
    def Print_Header(self):
        if type(self.collection) is Collector:
            print(Fore.LIGHTGREEN_EX + "\n\n\tProcessed Information: " + Fore.LIGHTYELLOW_EX + self.collection.Get_Name() + Style.RESET_ALL)
            print(Fore.GREEN + "\t-----------------------" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + "\n\t[?] " + Fore.LIGHTGREEN_EX + "Total Packets : " + Fore.LIGHTGREEN_EX + str(self.collection.packet_count()) + Style.RESET_ALL)
        else:
            print(Fore.LIGHTGREEN_EX + "\n\tTotal Directory Information" + Style.RESET_ALL)
            print(Fore.GREEN + "\t-----------------------" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + "\n\t[?] " + Fore.LIGHTYELLOW_EX + "Total Packets : " + Fore.LIGHTGREEN_EX + str(self.collection.Capture_Total_Count()) + Style.RESET_ALL)
        print(Fore.GREEN + "\t-------------" + Style.RESET_ALL)
        return
    #endregion

    #region Print Http Info
    def Print_HttpInfo(self):
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpInfo()) != False:
                print("\n\t\t-------------")
                print(Fore.LIGHTGREEN_EX + "\t\t[-] " + Fore.LIGHTYELLOW_EX + "HTTP Information" + Style.RESET_ALL)
                print("\t\t-------------")
                httpInfo = self.collection.getHttpInfo()
                for url in httpInfo:
                    print("\t\tURL: %s" % (url))
                    print("\t\tIP Addresses: %s: " % (httpInfo[url]["IP"]))
                    print(Fore.LIGHTGREEN_EX + "\n\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Header Information: Sent" + Style.RESET_ALL)
                    print(Fore.GREEN + "\t\t\t-------------" + Style.RESET_ALL)
                    for header in httpInfo[url]["Sent"]:
                        for line in header:
                            print("\t\t\t\t%s : %s" % (line, header[line]))

                    print(Fore.LIGHTGREEN_EX + "\n\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Header Information: Received" + Style.RESET_ALL)
                    print(Fore.GREEN + "\t\t\t-------------" + Style.RESET_ALL)
                    for header in httpInfo[url]["Recv"]:
                        for line in header:
                            print("\t\t\t\t%s : %s" % (line, header[line]))

                    print(Fore.LIGHTGREEN_EX + "\n\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Header Information: Data" + Style.RESET_ALL)
                    print(Fore.GREEN + "\t\t\t-------------" + Style.RESET_ALL)
                    for header in httpInfo[url]["Data-Text-Line"]:
                        for head in header:
                            print("\t\t\t\t%s" % (head))
                    print("\n\n")
        return
    #endregion

    #region Print Http Malformed Headers
    def Print_HttpMalformedHeaders(self):
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
    def Print_TCP(self):
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
        else:
            fp = self.collection.Capture_Filtered_Protocols()

        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "TCP : " + Fore.LIGHTGREEN_EX + str(sum(fp["TCP"].values())) + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
            
        for t in fp["TCP"].keys():
            print(Fore.LIGHTYELLOW_EX + "\t\t\t" + t + Fore.LIGHTGREEN_EX +  " -> " + Fore.CYAN + str(fp["TCP"][t]) + Style.RESET_ALL)
            print("\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.collection.packet_count() * 100)))
        return
    #endregion

    #region Print SSL/TLS Information
    def Print_SSLTLS(self):
        if type(self.collection) is Collector:
            sslTLS = self.collection.ssltls()
        else:
            sslTLS = self.collection.Capture_TLS()


        if bool(sslTLS) is True:
            print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "SSL/TLS Version : " + Fore.LIGHTGREEN_EX + str(sum(sslTLS.values())) + Style.RESET_ALL)
            print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
            for k, v in sslTLS.items():
                print(Fore.LIGHTYELLOW_EX + "\t\t\t" + k + Fore.LIGHTGREEN_EX + " -> " + Fore.CYAN + str(v) + Style.RESET_ALL)
                printf("\t\t\t{:.2f}%".format((v / (sum(sslTLS.values())) * 100)))
        return
    #endregion

    #region Print UDP Information
    def Print_UDP(self):
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
        else:
            fp = self.collection.Capture_Filtered_Protocols()
        
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "UDP : " + Fore.LIGHTGREEN_EX + str(sum(fp["UDP"].values())) + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)

        for t in fp["UDP"].keys():
            print(Fore.LIGHTYELLOW_EX + "\t\t\t" + t + Fore.LIGHTGREEN_EX + " -> " + Fore.CYAN + str(fp["UDP"][t]) + Style.RESET_ALL)
            print("\t\t\t{0:.2f}%".format((fp["UDP"][t] / self.collection.packet_count() * 100)))
        return
    #endregion

    #region Print LLC Information
    def Print_LLC(self):
        header1 = Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "LLC" + Style.RESET_ALL
        header2 = Fore.GREEN + "\t\t-------------" + Style.RESET_ALL

        if type(self.collection) is Collector:
            up = self.collection.filtered_protocols()
            if bool(up["LLC"]) is True:
                print(header1)
                print(header2)
                for t in up["LLC"].keys():
                    print("\t\t\t%s -> %s" % (t, up["LLC"][t]))
                    print("\t\t\t{0:.2f}%".format((up["LLC"][t] / self.collection.packet_count() * 100)))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            if bool(fp["LLC"]) is True:
                print(header1)
                print(header2)
                for t in self.collection.Capture_Filtered_Protocols()["LLC"].keys():
                    print("\t\t\t%s -> %s" % (t, fp["LLC"][t]))
                    print("\t\t\t{0:.2f}%".format((fp["LLC"][t] / self.collection.packet_count() * 100)))
        return
    #endregion

    #region Print Other Protocols
    def Print_Other_Protocols(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "In Depth View (All Protocols)" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
        else:
            fp = self.collection.Capture_Filtered_Protocols()

        for t in fp["OTHER"].keys():
            print(Fore.LIGHTYELLOW_EX + "\t\t\t" + t + Fore.LIGHTGREEN_EX + " -> " + Fore.CYAN + str(fp["OTHER"][t]) + Style.RESET_ALL)
            print("\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.collection.packet_count() * 100)))
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
    def Print_IPS_Filtered(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "IP Addresses (Filtered)" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        evn = 0
        if type(self.collection) is Collector:
            collected = self.collection.ip_addresses_filtered()
        else:
            collected = self.collection.Capture_IP_Filtered()
        
        for snt in collected.keys():
            ips = snt.split(" -> ")
            print(Fore.LIGHTYELLOW_EX + "\t\t\t" + ips[0] + Fore.LIGHTGREEN_EX + " -> " + Fore.LIGHTYELLOW_EX + ips[-1] + Fore.LIGHTWHITE_EX + " : " + Fore.CYAN + str(collected[snt]) + Style.RESET_ALL)
            evn += 1
            if (evn % 2) == 0:
                print("\n")
        return
    #endregion

    #region Print FQDN Information
    def Print_FQDN(self):
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