#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import os
import sys
import platform
import colorama 
from colorama import Fore, Back, Style
from application.classes.Collectors.Collector import Collector
from .Totals import Totals
from .Writer import Writer
from application.classes.Helpers.Opener import FolderOpener
from application.classes.Structure.FolderStruct import FolderStruct
from application.classes.Helpers.PrinterBase import PrinterBase

class Saver(Collector, Totals):
    #regoin Init For Class
    def __init__(self, capts, do_fqdn):
        self.capts = capts
        self.do_fqdn = do_fqdn
        # self.folderStruct = kwargs.get("Folders", None)
        self.save_file_name = capts.get_name()
        self.path = FolderOpener().totals + "/" + capts.get_namestripped() + "/"

        self.printerBase = PrinterBase()
        # print(os.path.exists(self.path))
        if not os.path.exists(self.path):
            if platform.system() != "windows":
                self.path = self.path.replace("\\", "/")
            if not os.path.exists(self.path):
                os.makedirs(self.path)
        
        # print(os.path.exists(self.path))
        # return
    #endregion
    
    #region Override for __str__ this returns a string
    def __str__(self):
        toSave = ""
        toSave += "%s\n" % self.Save_Header()
        toSave += "\n%s" % self.Save_TCP()
        
        if self.Save_SSLTLS() != None:
            toSave += "\n%s" % self.Save_SSLTLS()

        toSave += "\n%s" % self.Save_UDP()

        if self.Save_LLC() != None:
            toSave += "\n%s" % self.Save_LLC()
        
        toSave += "\n%s" % self.Save_Other_Protocols()
        toSave += "\n%s" % self.Save_IPS_Filtered()
        if self.do_fqdn is True:
            toSave += "\n%s" % self.Save_FQDN()

        if self.Save_HttpInfo() != None:
            toSave += "\n%s" % self.Save_HttpInfo()

        if self.Save_HttpMalformedHeaders() != None:
            toSave += "\n%s" % self.Save_HttpMalformedHeaders()
        return toSave
    #endregion

    #region Save
    def Save(self):
        self.printerBase.print_formatted_sub_header("Saving Data")
        # print(Fore.LIGHTGREEN_EX + "\t\t-------------------------------" + Style.RESET_ALL)
        saveIPFilters = Writer(self.save_file_name + "-Filtered-IPS", self.Save_IPS_Filtered(), "w+", infoname = "Filtered IPS", path = self.path)
        saveIPFilters.Save_Info()

        if self.do_fqdn is True:
            saveFQDN = Writer(self.save_file_name + "-IPS-FQDN", self.Save_FQDN(), "w+", infoname = "IPs to FQDN", path = self.path)
            saveFQDN.Save_Info()
        
        if self.Save_SSLTLS() != None:
            saveSSLTLS = Writer(self.save_file_name + "-SSL-TLS", self.Save_SSLTLS(), "w+", infoname = "SSL/TLS", path = self.path)
            saveSSLTLS.Save_Info()

        if self.Save_LLC() != None:
            saveLLC = Writer(self.save_file_name + "-LLC", self.Save_LLC(), "w+", infoname = "LLC", path = self.path)
            saveLLC.Save_Info()
        
        saveTCP = Writer(self.save_file_name + "-TCP", self.Save_TCP(), "w+", infoname = "TCP", path = self.path)
        saveTCP.Save_Info()

        saveUDP = Writer(self.save_file_name + "-UDP", self.Save_UDP(), "w+", infoname = "UDP", path = self.path)
        saveUDP.Save_Info()

        saveOtherProtcols = Writer(self.save_file_name + "-Other-Protocols", self.Save_Other_Protocols(), "w+", infoname = "Other Protocols", path = self.path)
        saveOtherProtcols.Save_Info()

        if self.Save_HttpInfo() != None:
            saveHttpInfo = Writer(self.save_file_name + "-Http-Info", self.Save_HttpInfo(), "w+", infoname = "HTTP Info", path = self.path)
            saveHttpInfo.Save_Info()

        if self.Save_HttpMalformedHeaders() != None:
            saveHttpMalformedHeaders = Writer(self.save_file_name + "-HTTP-Malformed-Headers", self.Save_HttpMalformedHeaders(), "w+", infoname = "Http Malformed Headers", path = self.path)
            saveHttpMalformedHeaders.Save_Info()

        print("\n")
        fileWriter = Writer(self.save_file_name, str(self), "w+", infoname = "All Data", path = self.path)
        fileWriter.Save()

        self.printerBase.print_horizontal_break()
        return
    #endregion

    #region Save Header Returns String
    def Save_Header(self):
        toSave = ""
        if type(self.capts) is Collector:
            toSave += "\n\t%s: %s" % ("Processed Information", self.capts.get_name())
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
                toSave += "\n\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.capts.packet_count() * 100))
        else:
            fp = self.capts.filtered_protocols()
            for t in fp["TCP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["TCP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["TCP"][t] / self.capts.Capture_Total_Count() * 100))
        return toSave
    #endregion
    
        
    #region Save SSL/TLS Information Returns String
    def Save_SSLTLS(self):
        toSave = "" 
        header = "\n\t\t[-] SSL/TLS Version"
        header += "\n\t\t-------------"
        if type(self.capts) is Collector:
            if bool(self.capts.ssltls()) is True:
                toSave += header
                for k, v in self.capts.ssltls().items():
                    toSave += "\n\t\t\t%s -> %s" % (k, v)
                    toSave += "\n\t\t\t{0:.2f}%".format((v / (sum(self.capts.ssltls().values())) * 100))
        else:
            if bool(self.capts.ssltls()) is True:
                toSave += header
                for k, v in self.capts.ssltls().items():
                    toSave += "\n\t\t\t%s -> %s" % (k, v)
                    toSave += "\n\t\t\t{0:.2f}%".format((v / (sum(self.capts.ssltls.values())) * 100))
        if toSave != "":
            return toSave
        else:
            return None
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
                toSave += "\n\t\t\t{0:.2f}%".format((up["UDP"][t] / self.capts.packet_count() * 100))
        else:
            fp = self.capts.filtered_protocols()
            fp = self.capts.filtered_protocols()
            for t in self.capts.filtered_protocols()["UDP"].keys():
                toSave += "\n\t\t\t%s -> %s" % (t, fp["UDP"][t])
                toSave += "\n\t\t\t{0:.2f}%".format((fp["UDP"][t] / self.capts.Capture_Total_Count() * 100))
        return toSave
    #endregion
    
    #region Save LLC Information Returns String
    def Save_LLC(self):
        toSave = ""
        header = "\n\t\t[-] LLC"
        header += "\n\t\t-------------"
        if type(self.capts) is Collector:
            up = self.capts.filtered_protocols()
            if bool(up["LLC"]) is True:
                toSave += header
                for t in up["LLC"].keys():
                    toSave += "\n\t\t\t%s -> %s" % (t, up["LLC"][t])
                    toSave += "\n\t\t\t{0:.2f}%".format((up["LLC"][t] / self.capts.totalLLC() * 100))
        else:
            fp = self.capts.filtered_protocols()
            if bool(fp["LLC"]) is True:
                toSave += header
                for t in fp["LLC"].keys():
                    toSave += "\n\t\t\t%s -> %s" % (t, fp["LLC"][t])
                    toSave += "\n\t\t\t{0:.2f}%".format((fp["LLC"][t] / self.capts.Capture_Total_Count() * 100))
        if toSave != "":
            return toSave
        else:
            return None
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
            fp = self.capts.filtered_protocols()
            for t in self.capts.filtered_protocols()["OTHER"].keys():
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
        # if type(self.capts) is Collector:
        #     evn = 0
        #     for snt in self.capts.ip_addresses_filtered().keys():
        #         toSave += "\n\t\t\t%s : %s" % (snt, self.capts.ip_addresses_filtered()[snt])
        #         evn += 1
        #         if (evn % 2) == 0:
        #             toSave += "\n"
        # else:
        evn = 0
        for snt in self.capts.ip_addresses_filtered().keys():
            toSave += "\n\t\t\t%s : %s" % (snt, self.capts.ip_addresses_filtered()[snt])
            evn += 1
            if (evn % 2) == 0:
                toSave += "\n"
        return toSave 
    #endregion
    
    #region Save FQDN Information Returns String
    def Save_FQDN(self):
        toSave = ""
        toSave += "\n\t\t[-] Fully Quailfied Domain Name (FQDN)"
        toSave += "\n\t\t-------------"
        if type(self.capts) is Collector:
            for fqdn in self.capts.fqdn().items():
                toSave += "\n\t\t\t" + fqdn[0] + " -> " + fqdn[1]
        else:
            for fqdn in self.capts.Capture_IP_FQDN().items():
                toSave += "\n\t\t\t" + fqdn[0] + " -> " + fqdn[1]

        return toSave
    #endregion

    #region Save Http Info Returns String
    def Save_HttpInfo(self):
        toSave = ""
        
        if type(self.capts) is Collector:
            if bool(self.capts.getHttpInfo()) != False:
                toSave += "\n\t\t-------------"
                toSave += "\n\t\t[-] HTTP Information"
                toSave += "\n\t\t-------------"

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
                    
                    if len(httpInfo[url]["Data-Text-Line"]) != 0:
                        toSave += "\n\t\t\t[-] Header Information: Data"
                        toSave += "\n\t\t\t-------------"
                        for header in httpInfo[url]["Data-Text-Line"]:
                            for head in header:
                                toSave += "\n\t\t\t\t%s" % (head)
                            toSave += "\n"
                            
                toSave += "\n\n"
        if toSave != "":
            return toSave
        else:
            return None
    #endregion

    #region Save Http Malformed Headers Returns String
    def Save_HttpMalformedHeaders(self):
        toSave = ""
        if type(self.capts) is Collector:
            if bool(self.capts.getHttpMalformedHeaders()) != False:
                toSave += "\n\t\t-------------"
                toSave += "\n\t\t[-] HTTP Malformed Headers"
                toSave += "\n\t\t-------------"
                headersMalformed = self.capts.getHttpMalformedHeaders()
                for url in headersMalformed:
                    toSave += "\n\t\t\tURL: %s" % (url)
                    toSave += "\n\t\t\t----------------------"
                    if bool(headersMalformed[url]["login"]) != False:
                        toSave += "\n\t\t\t\tLog In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["login"]:
                            toSave += "\n\t\t\t\t\tLog In: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["login"][pktnum])
                    if bool(headersMalformed[url]["job"]) != False:
                        toSave += "\n\n\t\t\t\tJob In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["job"]:
                            toSave += "\n\t\t\t\t\tJob: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["job"][pktnum])
                    if bool(headersMalformed[url]["keepalived"]) != False:
                        toSave += "\n\n\t\t\t\tKeep Alive In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["keepalived"]:
                            toSave += "\n\t\t\t\t\tKeep Alive: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["keepalived"][pktnum])
                    if bool(headersMalformed[url]["submit"]) != False:
                        toSave += "\n\n\t\t\t\tSubmit In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["submit"]:
                            toSave += "\n\t\t\t\t\tSubmit: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["submit"][pktnum])
                    if bool(headersMalformed[url]["error"]) != False:
                        toSave += "\n\n\t\t\t\tError In Headers"
                        toSave += "\n\t\t\t\t-------------"
                        for pktnum in headersMalformed[url]["error"]:
                            toSave += "\n\t\t\t\t\tError: PKT Num: %s : %s" % (pktnum, headersMalformed[url]["error"][pktnum])
                    toSave += "\n\n"
        if toSave != "":
            return toSave
        else:
            return None
    #endregion