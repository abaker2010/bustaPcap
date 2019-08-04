#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import sys
import colorama 
from colorama import Fore, Back, Style
from classes.Collector import Collector
from classes.Totals import Totals

class Saver(Collector, Totals):
    #regoin Init For Class
    def __init__(self, capts, do_fqdn, *args, **kwargs):
        self.capts = capts
        self.do_fqdn = do_fqdn
        return
    #endregion
       
    #region Save Collector Information Returns String
    def Save_Collector(self):
        toSave = ""
        toSave += "%s\n" % self.Save_Header()
        toSave += "\n%s" % self.Save_TCP()
        toSave += "\n%s" % self.Save_SSLTLS()
        toSave += "\n%s" % self.Save_UDP()
        toSave += "\n%s" % self.Save_LLC()
        toSave += "\n%s" % self.Save_Other_Protocols()
        toSave += "\n%s" % self.Save_IPS_Filtered()
        if self.do_fqdn is True:
            toSave += "\n%s" % self.Save_FQDN()
        toSave += "\n%s" % self.Save_HttpInfo()
        toSave += "\n%s" % self.Save_HttpMalformedHeaders()
        return toSave
    #endregion

    #region Save Header Returns String
    def Save_Header(self):
        toSave = ""
        if type(self.capts) is Collector:
            toSave += "\n\t%s: %s" % ("Processed Information", self.capts.Get_Name())
            toSave += "\n\t-----------------------"
            toSave += "\n\t\t%s: %s" % ("[?] Total Packets", self.capts.packet_count())
        else:
            toSave += "\n\t%s" % ("Total Directory Information")
            toSave += "\n\t-----------------------"
            toSave += "\n\t\t%s: %s" % ("[?] Total Packets", self.capts.Capture_Total_Count())
        return toSave
    #endregion

    #region Save TCP Information
    def Save_TCP(self):
        toSave = ""
        toSave += "\n\t\t-------------"
        toSave += "\n\t\t[-] TCP"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            fp = self.capts.filtered_protocols()
            for t in fp["TCP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["TCP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.capts.totalTCP() * 100))
        else:
            fp = self.capts.Capture_Filtered_Protocols()
            for t in fp["TCP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["TCP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.capts.Total_TCP() * 100))
        return toSave
    #endregion
    
        
    #region Save SSL/TLS Information Returns String
    def Save_SSLTLS(self):
        toSave = "" 
        toSave += "\n\t\t[-] SSL/TLS Version"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            for k, v in self.capts.ssltls().items():
                toSave += "\n\t\t\t%s -> %s" % (k, v)
        else:
            for k, v in self.capts.Capture_TLS().items():
                toSave += "\n\t\t\t%s -> %s" % (k, v)
        return toSave
    #endregion

    
    #region Save UDP Information Returns String
    def Save_UDP(self):
        toSave = ""
        toSave += "\n\t\t[-] UDP"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            up = self.capts.filtered_protocols()
            for t in up["UDP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, up["UDP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((up["UDP"][t] / self.capts.totalUDP() * 100))
        else:
            fp = self.capts.Capture_Filtered_Protocols()
            for t in self.capts.Capture_Filtered_Protocols()["UDP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["UDP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["UDP"][t] / self.capts.Total_UDP() * 100))
        return toSave
    #endregion
    
    #region Save LLC Information Returns String
    def Save_LLC(self):
        toSave = ""
        toSave += "\n\t\t[-] LLC"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            up = self.capts.filtered_protocols()
            for t in up["LLC"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, up["LLC"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((up["LLC"][t] / self.capts.totalLLC() * 100))
        else:
            fp = self.capts.Capture_Filtered_Protocols()
            for t in self.capts.Capture_Filtered_Protocols()["LLC"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["LLC"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["LLC"][t] / self.capts.Total_LLC() * 100))
        return toSave
    #endregion
    
    #region Save Other Protocols Returns String
    def Save_Other_Protocols(self):
        toSave = ""
        toSave += "\n\t\t[-] In Depth View (All Protocols)"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            fp = self.capts.filtered_protocols()
            for t in fp["OTHER"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["OTHER"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.capts.packet_count() * 100))
        else:
            fp = self.capts.Capture_Filtered_Protocols()
            for t in self.capts.Capture_Filtered_Protocols()["OTHER"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["OTHER"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["OTHER"][t] / self.capts.Capture_Total_Count() * 100))
        return toSave
    #endregions
    
    #region Save IPS Information Returns String
    def Save_IPS(self):
        toSave = ""
        toSave += "\n\t\t[-] IP Addresses"
        toSave += "\n\t\t-------------"
        for snt in self.capts.ip_addresses_only():
                toSave += "\n\t\t\t%s" % (snt) 
        return toSave
    #endregion
    
    #region Save IPS Filtered Information Returns String
    def Save_IPS_Filtered(self):
        toSave = ""
        toSave += "\n\t\t[-] IP Addresses (Filtered)"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            evn = 0
            for snt in self.capts.ip_addresses_filtered().keys():
                toSave += "\n\t\t\t%s : %s" % (snt, self.capts.ip_addresses_filtered()[snt])
                evn += 1
                if (evn % 2) == 0:
                    toSave += "\n"
        else:
            evn = 0
            for snt in self.capts.Capture_IP_Filtered().keys():
                toSave += "\n\t\t\t%s : %s" % (snt, self.capts.Capture_IP_Filtered()[snt])
                evn += 1
                if (evn % 2) == 0:
                    toSave += "\n"
        return toSave 
    #endregion
    
    #region Save Http Info Returns String
    def Save_HttpInfo(self):
        toSave = ""
        toSave += "\n\t\t-------------"
        toSave += "\n\t\t[-] HTTP Information"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            if bool(self.capts.getHttpInfo()) is not False:
                httpInfo = self.capts.getHttpInfo()
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
    #endregion

    #region Save Http Malformed Headers Returns String
    def Save_HttpMalformedHeaders(self):
        toSave = ""
        if type(self.capts) is Collector:
            if bool(self.capts.getHttpMalformedHeaders()) is not False:
                toSave += "\n\t\t-------------"
                toSave += "\n\t\t[-] HTTP Malformed Headers"
                toSave += "\n\t\t-------------"
                headersMalformed = self.capts.getHttpMalformedHeaders()
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
    #endregion