#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import sys
from classes.Collector import Collector
from classes.Totals import Totals
import colorama 
from colorama import Fore, Back, Style

class Print:
    def __init__(self, collection, fqdn):
        self.collection = collection
        self.fqdnbool = fqdn
        return

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

    def Save_Printer(self):
        toSave = ""
        toSave += "%s\n" % self.Save_Header()
        toSave += "\n%s" % self.Save_TCP()
        toSave += "\n%s" % self.Save_SSLTLS()
        toSave += "\n%s" % self.Save_UDP()
        toSave += "\n%s" % self.Save_LLC()
        toSave += "\n%s" % self.Save_Other_Protocols()
        toSave += "\n%s" % self.Save_IPS_Filtered()
        if self.fqdnbool is True:
            toSave += "\n%s" % self.Save_FQDN()
        toSave += "\n%s" % self.Save_HttpInfo()
        toSave += "\n%s" % self.Save_HttpMalformedHeaders()
        return toSave

    def Print_Header(self):
        if type(self.collection) is Collector:
            print(Fore.LIGHTGREEN_EX + "\n\n\tProcessed Information: " + Fore.LIGHTYELLOW_EX + self.collection.Get_Name() + Style.RESET_ALL)
            print(Fore.GREEN + "\t-----------------------" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + "\n\t\t[?] " + Fore.LIGHTGREEN_EX + "Total Packets : " + Fore.LIGHTYELLOW_EX + str(self.collection.packet_count()) + Style.RESET_ALL)
        else:
            print("\n\t%s" % ("Total Directory Information"))
            print(Fore.GREEN + "\t-----------------------" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + "\n\t\t[?] " + Style.RESET_ALL + "Total Packets : " + Fore.LIGHTYELLOW_EX + str(self.collection.Capture_Total_Count()) + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        return

    def Save_Header(self):
        toSave = ""
        if type(self.collection) is Collector:
            toSave += "\n\t%s: %s" % ("Processed Information", self.collection.Get_Name())
            toSave += "\n\t-----------------------"
            toSave += "\n\t\t%s: %s" % ("[?] Total Packets", self.collection.packet_count())
        else:
            toSave += "\n\t%s" % ("Total Directory Information")
            toSave += "\n\t-----------------------"
            toSave += "\n\t\t%s: %s" % ("[?] Total Packets", self.collection.Capture_Total_Count())
        return toSave

    def Print_HttpInfo(self):
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpInfo()) is not False:
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

    def Save_HttpInfo(self):
        toSave = ""
        toSave += "\n\t\t-------------"
        toSave += "\n\t\t[-] HTTP Information"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpInfo()) is not False:
                httpInfo = self.collection.getHttpInfo()
                for url in httpInfo:
                    toSave += "\n\n\t\tURL: %s" % (url)
                    toSave += "\n\t\tIP Addresses: %s: " % (httpInfo[url]["IP"])
                    toSave += "\n\t\t\t[-] Header Information: Sent"
                    toSave += "\n\t\t\t-------------"
                    for header in httpInfo[url]["Sent"]:
                        for line in header:
                            toSave += "\n\t\t\t\t%s : %s" % (line, header[line])
                        toSave += "\n"

                    toSave += "\n\t\t\t[-] Header Information: Received"
                    toSave += "\n\t\t\t-------------"
                    for header in httpInfo[url]["Recv"]:
                        for line in header:
                            toSave += "\n\t\t\t\t%s : %s" % (line, header[line])
                        toSave += "\n"
                    
                    if len(httpInfo[url]["Data-Text-Line"]) is not 0:
                        toSave += "\n\t\t\t[-] Header Information: Data"
                        toSave += "\n\t\t\t-------------"
                        for header in httpInfo[url]["Data-Text-Line"]:
                            for head in header:
                                toSave += "\n\t\t\t\t%s" % (head)
                            toSave += "\n"
            else:
                toSave += "\n\t\t\tNo Information Found"
                            
        toSave += "\n\n"

        return toSave

    def Print_HttpMalformedHeaders(self):
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpMalformedHeaders()) is not False:
                
                print(Fore.LIGHTGREEN_EX + "\t\t[-] " + Fore.LIGHTYELLOW_EX + "HTTP Malformed Headers" + Style.RESET_ALL)
                print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
                headersMalformed = self.collection.getHttpMalformedHeaders()
                for url in headersMalformed:
                    print(Fore.LIGHTGREEN_EX + "\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "URL: " + Fore.LIGHTCYAN_EX + url + Style.RESET_ALL)
                    print(Fore.GREEN + "\t\t\t----------------------" + Style.RESET_ALL)
                    if bool(headersMalformed[url]["login"]) is not False:
                        print(Fore.LIGHTGREEN_EX + "\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Log In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL)
                        for pktnum in headersMalformed[url]["login"]:
                            print("\t\t\t\t\tLog In: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["login"][pktnum]))
                    if bool(headersMalformed[url]["job"]) is not False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Job In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["job"]:
                            print("\t\t\t\t\tJob: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["job"][pktnum]))
                    if bool(headersMalformed[url]["keepalived"]) is not False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Keep Alive In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["keepalived"]:
                            print("\t\t\t\t\tKeep Alive: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["keepalived"][pktnum]))
                    if bool(headersMalformed[url]["submit"]) is not False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Submit In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["submit"]:
                            print("\t\t\t\t\tSubmit: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["submit"][pktnum]))
                    if bool(headersMalformed[url]["error"]) is not False:
                        print(Fore.LIGHTGREEN_EX + "\n\t\t\t\t[-] " + Fore.LIGHTYELLOW_EX + "Error In Headers" + Style.RESET_ALL)
                        print(Fore.GREEN + "\t\t\t\t-------------" + Style.RESET_ALL) 
                        for pktnum in headersMalformed[url]["error"]:
                            print("\t\t\t\t\tError: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["error"][pktnum]))
                    print("\n\n")
        return

    def Save_HttpMalformedHeaders(self):
        toSave = ""
        if type(self.collection) is Collector:
            if bool(self.collection.getHttpMalformedHeaders()) is not False:
                toSave += "\n\t\t-------------"
                toSave += "\n\t\t[-] HTTP Malformed Headers"
                toSave += "\n\t\t-------------"
                headersMalformed = self.collection.getHttpMalformedHeaders()
                for url in headersMalformed:
                    toSave += "\n\t\t\tURL: %s" % (url)
                    toSave += "\n\t\t\t----------------------"
                    if bool(headersMalformed[url]["login"]) is not False:
                        toSave += "\n\t\t\t\tLog In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["login"]:
                            toSave += "\n\t\t\t\t\tLog In: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["login"][pktnum])
                    if bool(headersMalformed[url]["job"]) is not False:
                        toSave += "\n\n\t\t\t\tJob In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["job"]:
                            toSave += "\n\t\t\t\t\tJob: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["job"][pktnum])
                    if bool(headersMalformed[url]["keepalived"]) is not False:
                        toSave += "\n\n\t\t\t\tKeep Alive In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["keepalived"]:
                            toSave += "\n\t\t\t\t\tKeep Alive: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["keepalived"][pktnum])
                    if bool(headersMalformed[url]["submit"]) is not False:
                        toSave += "\n\n\t\t\t\tSubmit In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["submit"]:
                            toSave += "\n\t\t\t\t\tSubmit: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["submit"][pktnum])
                    if bool(headersMalformed[url]["error"]) is not False:
                        toSave += "\n\n\t\t\t\tError In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["error"]:
                            toSave += "\n\t\t\t\t\tError: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["error"][pktnum])
                    toSave += "\n\n"
        return toSave

    def Print_TCP(self):
        #print("\t\t-------------")
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "TCP" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
            for t in fp["TCP"].keys():
                print("\t\t\t%s -> %s" % (t, fp["TCP"][t]))
                print("\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.collection.totalTCP() * 100)))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in fp["TCP"].keys():
                print("\t\t\t%s -> %s" % (t, fp["TCP"][t]))
                print("\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.collection.Total_TCP() * 100)))
        return

    def Save_TCP(self):
        toSave = ""
        toSave += "\n\t\t-------------"
        toSave += "\n\t\t[-] TCP"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
            for t in fp["TCP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["TCP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.collection.totalTCP() * 100))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in fp["TCP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["TCP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.collection.Total_TCP() * 100))
        return toSave

    def Print_SSLTLS(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "SSL/TLS Version" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            for k, v in self.collection.ssltls().items():
                print("\t\t\t%s -> %s" % (k, v))
        else:
            for k, v in self.collection.Capture_TLS().items():
                print("\t\t\t%s -> %s" % (k, v))
        return
    
    def Save_SSLTLS(self):
        toSave = "" 
        toSave += "\n\t\t[-] SSL/TLS Version"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            for k, v in self.collection.ssltls().items():
                toSave += "\n\t\t\t%s -> %s" % (k, v)
        else:
            for k, v in self.collection.Capture_TLS().items():
                toSave += "\n\t\t\t%s -> %s" % (k, v)
        return toSave

    def Print_UDP(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "UDP" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            up = self.collection.filtered_protocols()
            for t in up["UDP"].keys():
                print("\t\t\t%s -> %s" % (t, up["UDP"][t]))
                print("\t\t\t{0:.2f}%".format((up["UDP"][t] / self.collection.totalUDP() * 100)))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in self.collection.Capture_Filtered_Protocols()["UDP"].keys():
                print("\t\t\t%s -> %s" % (t, fp["UDP"][t]))
                print("\t\t\t{0:.2f}%".format((fp["UDP"][t] / self.collection.Total_UDP() * 100)))
        return

    def Save_UDP(self):
        toSave = ""
        toSave += "\n\t\t[-] UDP"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            up = self.collection.filtered_protocols()
            for t in up["UDP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, up["UDP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((up["UDP"][t] / self.collection.totalUDP() * 100))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in self.collection.Capture_Filtered_Protocols()["UDP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["UDP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["UDP"][t] / self.collection.Total_UDP() * 100))
        return toSave

    def Print_LLC(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "LLC" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            up = self.collection.filtered_protocols()
            for t in up["LLC"].keys():
                print("\t\t\t%s -> %s" % (t, up["LLC"][t]))
                print("\t\t\t{0:.2f}%".format((up["LLC"][t] / self.collection.totalLLC() * 100)))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in self.collection.Capture_Filtered_Protocols()["LLC"].keys():
                print("\t\t\t%s -> %s" % (t, fp["LLC"][t]))
                print("\t\t\t{0:.2f}%".format((fp["LLC"][t] / self.collection.Total_LLC() * 100)))
        return

    def Save_LLC(self):
        toSave = ""
        toSave += "\n\t\t[-] LLC"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            up = self.collection.filtered_protocols()
            for t in up["LLC"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, up["LLC"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((up["LLC"][t] / self.collection.totalLLC() * 100))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in self.collection.Capture_Filtered_Protocols()["LLC"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["LLC"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["LLC"][t] / self.collection.Total_LLC() * 100))
        return toSave

    def Print_Other_Protocols(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "In Depth View (All Protocols)" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
            for t in fp["OTHER"].keys():
                print("\t\t\t%s -> %s" % (t, fp["OTHER"][t]))
                print("\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.collection.packet_count() * 100)))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in self.collection.Capture_Filtered_Protocols()["OTHER"].keys():
                print("\t\t\t%s -> %s" % (t, fp["OTHER"][t]))
                print("\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.collection.Capture_Total_Count() * 100)))
        return

    def Save_Other_Protocols(self):
        toSave = ""
        toSave += "\n\t\t[-] In Depth View (All Protocols)"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            fp = self.collection.filtered_protocols()
            for t in fp["OTHER"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["OTHER"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.collection.packet_count() * 100))
        else:
            fp = self.collection.Capture_Filtered_Protocols()
            for t in self.collection.Capture_Filtered_Protocols()["OTHER"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["OTHER"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.collection.Capture_Total_Count() * 100))
        return toSave

    def Print_IPS(self):
        print("\n\t\t[-] IP Addresses")
        print("\t\t-------------")
        for snt in self.collection.ip_addresses_only():
                print("\t\t\t%s" % (snt) )
        return

    def Save_IPS(self):
        toSave = ""
        toSave += "\n\t\t[-] IP Addresses"
        toSave += "\n\t\t-------------"
        for snt in self.collection.ip_addresses_only():
                toSave += "\n\t\t\t%s" % (snt) 
        return toSave

    def Print_IPS_Filtered(self):
        print(Fore.LIGHTGREEN_EX + "\n\t\t[-] " + Fore.LIGHTYELLOW_EX + "IP Addresses (Filtered)" + Style.RESET_ALL)
        print(Fore.GREEN + "\t\t-------------" + Style.RESET_ALL)
        if type(self.collection) is Collector:
            evn = 0
            for snt in self.collection.ip_addresses_filtered().keys():
                print("\t\t\t%s : %s" % (snt, self.collection.ip_addresses_filtered()[snt]))
                evn += 1
                if (evn % 2) == 0:
                    print("\n")
        else:
            evn = 0
            for snt in self.collection.Capture_IP_Filtered().keys():
                print("\t\t\t%s : %s" % (snt, self.collection.Capture_IP_Filtered()[snt]))
                evn += 1
                if (evn % 2) == 0:
                    print("\n")
        return

    def Save_IPS_Filtered(self):
        toSave = ""
        toSave += "\n\t\t[-] IP Addresses (Filtered)"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            evn = 0
            for snt in self.collection.ip_addresses_filtered().keys():
                toSave += "\n\t\t\t%s : %s" % (snt, self.collection.ip_addresses_filtered()[snt])
                evn += 1
                if (evn % 2) == 0:
                    toSave += "\n"
        else:
            evn = 0
            for snt in self.collection.Capture_IP_Filtered().keys():
                toSave += "\n\t\t\t%s : %s" % (snt, self.collection.Capture_IP_Filtered()[snt])
                evn += 1
                if (evn % 2) == 0:
                    toSave += "\n"
        return toSave 

    def Print_FQDN(self):
        print("\n\t\t[-] IP Addresses -> FQDN")
        print("\t\t-------------")
        if type(self.collection) is Collector:
            for k, v in sorted(self.collection.fqdn().items()):
                print("\t\t\t%s : %s" % (k, v))
        else:
            for k, v in sorted(self.collection.Capture_IP_FQDN().items()):
                print("\t\t\t%s : %s" % (k, v))
        return

    def Save_FQDN(self):
        toSave = ""
        toSave += "\n\t\t[-] IP Addresses -> FQDN"
        toSave += "\n\t\t-------------"
        if type(self.collection) is Collector:
            for k, v in sorted(self.collection.fqdn().items()):
                toSave += "\n\t\t\t%s : %s" % (k, v)
        else:
            for k, v in sorted(self.collection.Capture_IP_FQDN().items()):
                toSave += "\n\t\t\t%s : %s" % (k, v)
        return toSave