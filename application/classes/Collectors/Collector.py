#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import sys
import os
import socket
import inspect
import platform
import re 
import ipaddress
import colorama 
from colorama import Fore, Back, Style
from application.classes.Helpers.Writer import Writer
from application.classes.Structure.FolderStruct import FolderStruct
from application.classes.Helpers.Opener import FolderOpener
from application.classes.Helpers.PrinterBase import PrinterBase

class Collector:
    #region Init for Collector
    def __init__(self, capts, filename):
    #region Class Variables
        self.printerBase = PrinterBase()
        #region Passed
        self.captureName = filename
        self.folderPath = FolderOpener().reports
        self.capts = capts
        #endregion

        #region Numerical
        self.packetCount = 0

        self.packetLayerCount = 0
        self.processedLayerCount = 0
        
        self.erroredCount = 0
        self.erroredLayerCount = 0
        
        self.udp = 0
        self.tcp = 0
        self.llc = 0
        self.other = 0
        #endregion
        
        #region Dictionaries 
        self.protocols = {}
        self.ipAddresses = {}
        self.ip_fqdn = {}
        self.httpInfo = {}
        self.httpMalformedHeaders = {}
        self.tls = {}
        self.lDict = {"TCP" : {}, "UDP" : {}, "LLC" : {}, "OTHER" : {} }
        self.tlsversion = {"0x00000002":"SSLv2", "0x00000300":"SSLv3", "0x00000301":"TLSv1.0",
                          "0x00000302":"TLSv1.1", "0x00000303":"TLSv1.2", "0x00000304":"TLSv1.3"}
        self.erroredLayer = {}
        #endregion

        #region Arrays
        self.llcList = ["llc", "stp", "dtp", "cdp"]
        self.udpList = ["udp", "ntp", "dns", "mdns", "ssdp", "browser", "nbns", "smb", "gquic", "dhcpv6"]
        self.tcpList = ["http", "tcp", "data-text-lines", "tls"]

        self._layerExceptions = ["ip", "eth", "tcp"]
        #endregion

        
        for pkt in self.capts:
            self.packetCount += 1
            sys.stdout.write(Fore.LIGHTCYAN_EX + "\r\t  [?] " + Fore.LIGHTGREEN_EX + "Packet Num : " + Fore.LIGHTYELLOW_EX + str(self.packetCount) + Style.RESET_ALL)
            
            try:
                src = self.packet_ip_src_dest(pkt)
                
                if src:
                    uri = None
                    for layer in pkt.layers:
                        self.packetLayerCount += 1
                        layerName = self.packet_layername(layer)
                        self.check_protocol(layerName)
                        try:
                            if layerName == "tls":
                                self.packet_tls(layer)
                            elif layerName == "udp":
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with udp: {e}")
                            elif layerName == "http":
                                try:
                                    if hasattr(layer, 'unkown_header'):
                                        print(f"Checking of crypto needs done here")
                                    # preint(f"Response code: \n {self.Check_Response_Code(layer, src)}")
                                    uri = self.check_response_code(layer, src)
                                except Exception as e:
                                    # print(f"\nIssue with http : {e}")
                                    # print(f"Layername : {src}")
                                    pass
                            elif layerName == "data-text-lines":
                                try:
                                    # print("Data text line needs read")
                                    self.packet_data_text_line(layer, uri)
                                except Exception as e:
                                    print(f"Issue with data-text-line : {e}")
                                    pass
                            elif layerName == "media":
                                try:
                                    # print("Media in pcap needs parsed")
                                    # print(uri)
                                    # print(f"\n\n{pkt}\n\n")
                                    self.check_media(layer, uri)
                                except Exception as e:
                                    print(f"Issue with media : {e}")
                                    print(Fore.RED + layer + Style.RESET_ALL)
                                    pass
                            elif layerName == "data":
                                try:
                                    # print(layer)
                                    pass
                                except Exception as e:
                                    print(f"Issue with data : {e}")
                                    pass
                            elif layerName == "telnet":
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with telnet: {e}")
                                    pass
                            elif layerName == "dns":
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with dns : {e}")
                                    pass
                            elif layerName == "mysql":
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with mysql : {e}")
                                    pass
                            elif layerName == "ipp":
                                # this is the 'Internet Printing Protocol"
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with ipp : {e}")
                                    pass
                            elif layerName == "ntp":
                                # network time not sure if we need to catch this
                                pass
                            elif layerName == "icmp":
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with icmp : {e}")
                                    pass
                            elif layerName == "ssh":
                                try:
                                    pass
                                except Exception as e:
                                    print(f"Issue with ssh : {e}")
                                    pass
                            else:
                                pass
                            self.processedLayerCount += 1

                        except Exception as e:
                            self.erroredLayerCount += 1
                            self.erroredLayer[self.packet_count] = layer
                            pass
                        
                        #     # else:
                        #     #     if layerName != "ip" and layerName != "tcp":
                        #     #         if layerName ==  "urlencoded-form":
                        #     #             self.Save_URLForm(pkt, uri)
                        #     #         elif layerName == "image-jfif":
                        #     #             self.Save_JFIF(pkt, uri)
                        #     #         elif layerName == "data":
                        #     #             print(pkt.data)
                        #     #         else:
                        #     #             print(layerName)

                        #     self.Check_Protocol(layerName)
                        # except Exception as e:
                        #     print("Layer Parser Error")
                        #     print(e)
                        #     pass
                        # return uri
                self.filtered_protocols()
                
            except Exception as e:
                # print(e)
                pass

            sys.stdout.flush()

        self.printerBase.print_formatted_body_item("DONE!", tabs=2, starting="\n\n") 
        self.printerBase.print_formatted_header(f"Processed {self.captureName} Cumulative Information", vtabs=2, headerColor=Fore.MAGENTA)
        self.printerBase.print_formatted_sub_header("Processed Success Ratio")
        self.printerBase.print_formatted_body_item("Total Packets: ", optionaltext=self.packetCount)
        self.printerBase.print_formatted_body_item("Total Layers: ", optionaltext=self.packetLayerCount)
        self.printerBase.print_formatted_body_item("Total Layers Processed: ", optionaltext=self.processedLayerCount)
        self.printerBase.print_formatted_body_item("Total Layers Errored: ", optionaltext=self.erroredLayerCount)
        self.printerBase.print_formatted_body_item("Success Layer Percentage: ", optionaltext=f"{round((((self.processedLayerCount - self.erroredLayerCount)/ self.processedLayerCount) * 100), 2)} %")

    #endregion 
    #endregion

    #region Parser for each layer
    # def Parse_Layer(self, pkt, src):
        # uri = None
        # try:
        #     layerName = self.packet_layername(pkt)
        #     print(layerName)

        #     if layerName == "tls":
        #         try:
        #             self.packet_tls(pkt)
        #         except Exception as tlsE:
        #             print(tlsE)
        #             pass
        #     elif layerName == "http":
        #         try:
        #             if hasattr(pkt, 'unknown_header') is True:
        #                 self.Check_Crypto(pkt, src)
        #             uri = self.Check_Response_Code(pkt, src)
        #         except Exception as e:
        #             pass

        # except Exception as e:
        #     print(e)
        # try:
        #     layerName = self.packet_layername(pkt)
        #     if layerName == "tls":
        #         try:
        #             self.Check_TLS(pkt)
        #         except Exception as e:
        #             pass
        #     elif layerName == "http":
        #         try:
        #             if hasattr(pkt, 'unknown_header') is True:
        #                 self.Check_Crypto(pkt, src)
        #             uri = self.Check_Response_Code(pkt, src)
        #         except Exception as e:
        #             pass
        #     elif layerName == "data-text-lines":
        #         try:
        #             self.Check_Data_Text(pkt, uri)
        #         except Exception as e:
        #             print("Data Layer Error")
        #             print(e)
        #             pass
        #     elif layerName == "media":
        #         try:
        #             self.Check_Media(pkt, uri)
        #         except Exception as e:
        #             print("Media Layer Error")
        #             print(e)
        #             pass
        #     # else:
        #     #     if layerName != "ip" and layerName != "tcp":
        #     #         if layerName ==  "urlencoded-form":
        #     #             self.Save_URLForm(pkt, uri)
        #     #         elif layerName == "image-jfif":
        #     #             self.Save_JFIF(pkt, uri)
        #     #         elif layerName == "data":
        #     #             print(pkt.data)
        #     #         else:
        #     #             print(layerName)

        #     self.Check_Protocol(layerName)
        # except Exception as e:
        #     print("Layer Parser Error")
        #     print(e)
        #     pass
        # return uri
    #endregion

    #region Check Source 
    def packet_ip_src_dest(self, pkt):
        src = ""
        try:
            src = pkt.ip.src + " -> " + pkt.ip.dst
        except Exception as e:
            pass

        if src in self.ipAddresses:
            self.ipAddresses[src] += 1
        else:
            self.ipAddresses[src] = 1
        return src
    #endregion

    #region Check LayerName
    def packet_layername(self, pkt):
        layerName = None
        if pkt._layer_name.lower() == "fake-field-wrapper":
            layerName = pkt.layer_name
        else:
            layerName = pkt._layer_name
        return layerName
    #endregion

    # def Save_JFIF(self, pkt, uri):
    #     dataString = ""
    #     try:
    #         folder = self.folderPath + "\\" + self.captureName.split('.')[0] + "\\"
    #         if platform.system() != "windows":
    #             folder = folder.replace("\\", "/")  
        
    #         fileSaver = Writer("URLForm-" + uri.replace('\\','-').replace('*','-').replace('?','-').replace('"','-').replace('<','-').replace('>','-').replace('/', '-').replace(':', '-').replace('|','-'), dataString, 'w', path = folder)
    #         fileSaver.Save_JFIF()
    #     except Exception as e:
    #         print("Error setting folder path")
    #         print(e)
    #     return


    # def Save_URLForm(self, pkt, uri):
    #     dataString = ""
    #     try:
    #         folder = self.folderPath + "\\" + self.captureName.split('.')[0] + "\\"
    #         if platform.system() != "windows":
    #             folder = folder.replace("\\", "/")  
    #         fileSaver = Writer("URLForm-" + uri.replace('\\','-').replace('*','-').replace('?','-').replace('"','-').replace('<','-').replace('>','-').replace('/', '-').replace(':', '-').replace('|','-'), dataString, 'w', path = folder)
    #         fileSaver.Save_Media()
    #     except Exception as e:
    #         print("Error setting folder path")
    #         print(e)
    #     return

    #region Check_Media
    def check_media(self, pkt, uri):
        dataString = ""
        try:
            bytes.fromhex(pkt.get_field_value('type').replace(':',''))
            # print("")
            # print(type(pkt.type))
            # print("")
            # print(dir(pkt))
            # print(bytes.fromhex(pkt.get_field_value('type').replace(':','')))
            # print(len(pkt.get_field_value('type')))
            # # print(pkt.type)
            # print("")
            # print(dir(pkt))
        except Exception as ee:
            print(Fore.RED + ee + "\n\n" + pkt.get_field_value('type') + Style.RESET_ALL)
            

        # for d in pkt.type.split(':'):
        #     dataString += str(bytes.fromhex(d), 'utf-8')
        try:
            folder = self.folderPath + "\\" + self.captureName.split('.')[0] + "\\"
            if platform.system() != "windows":
                folder = folder.replace("\\", "/")  

            data = bytes.fromhex(pkt.get_field_value('type').replace(':',''))
            print(type(data))
            # print(folder)
            fileSaver = Writer("Media-" + uri.replace('\\','-').replace('*','-').replace('?','-').replace('"','-').replace('<','-').replace('>','-').replace('/', '-').replace(':', '-').replace('|','-'), data, 'wb', path = folder)
            fileSaver.Save_Media()
        except Exception as e:
            print("Error setting folder path")
            print(e)
            print(Fore.RED + pkt.get_field_value('type') + Style.RESET_ALL)
        return
    #endregion

    #region Response Code Checker
    def check_response_code(self, pkt, src):
        info = {}
        uri = ""
        for field_line in pkt._get_all_field_lines():
            if ':' in field_line:
                field_name, field_line = field_line.split(':', 1)
                info[field_name.strip()] = field_line.strip().replace('\\r', '').replace('\\n', '')
        if hasattr(pkt, 'response_code') is True:
            if pkt.response_for_uri not in self.httpInfo:
                self.httpInfo[pkt.response_for_uri] = { "IP" : src, "Sent" : [], "Recv" : [info], "Data-Text-Line" : []}
            else: 
                self.httpInfo[pkt.response_for_uri]["Recv"].append(info)
            uri = pkt.response_for_uri
        else: 
            if pkt.request_full_uri not in self.httpInfo:
                self.httpInfo[pkt.request_full_uri] = { "IP" : src, "Sent" : [info], "Recv" : [], "Data-Text-Line" : []}
            else: 
                self.httpInfo[pkt.request_full_uri]["Sent"].append(info)
            uri = pkt.request_full_uri
        
        return uri
    #endregion 

    # Todo: Finish reimplimentation of cryptojacking. Testing needs done before pushing this
    #region Cryptojacking Checker
    def Check_Crypto(self, pkt, src):
        # wire shark is getting this mixed up with a bad header so that is why it is showing funny in the 
        # program not their fault but is it because the coin miner is able to by pass firewalls and such this way
        # In here needs to be regex parser try catchs for each one found then 
        # have a dict like {Loging : {}, Job : {}, Error : {}}
        # use the json to c# to build the needed objects that the logic will need

        # in each instance this needs to add information to the httpinfo dict in the malform header section
        # then when printing the malformed header needs to be checked and printed if there is any information to be displayed

        result = re.compile(r'{"jsonrpc":"\d.\d","method":"(\w+)","params":{(.+)}}', re.IGNORECASE)
        m = result.match(str(pkt.unknown_header))
        if m:
            # so far have only found 'job' for the method
            if src not in self.httpMalformedHeaders:
                self.httpMalformedHeaders[src] = {"login" : {}, "job" : {self.packetCount : m.group()}, "keepalived" : {}, "submit" : {}, "error" : {}}
            else:
                self.httpMalformedHeaders[src]["job"][self.packetCount] = m.group()

        if m is None:
            result = re.compile(r'{"id":\d+,"jsonrpc":"\d.\d","method":"(\w+)","params":{(.+)}}', re.IGNORECASE)
            m = result.match(str(pkt.unknown_header))
            if m:
                # so far have found 'login', 'keepalived', 'submit'
                if m.group(1) == "login":
                    if src not in self.httpMalformedHeaders:
                        self.httpMalformedHeaders[src] = {"login" : {self.packetCount : m.group()}, "job" : {}, "keepalived" : {}, "submit" : {}, "error" : {}}
                    else:
                        self.httpMalformedHeaders[src]["login"][self.packetCount] = m.group()
                elif m.group(1) == 'keepalived':
                    if src not in self.httpMalformedHeaders:
                        self.httpMalformedHeaders[src] = {"login" : {}, "job" : {}, "keepalived" : {self.packetCount : m.group()}, "submit" : {}, "error" : {}}
                    else:
                        self.httpMalformedHeaders[src]["keepalived"][self.packetCount] = m.group()
                elif m.group(1) == 'submit':
                    if src not in self.httpMalformedHeaders:
                        self.httpMalformedHeaders[src] = {"login" : {}, "job" : {}, "keepalived" : {}, "submit" : {self.packetCount : m.group()}, "error" : {}}
                    else:
                        self.httpMalformedHeaders[src]["submit"][self.packetCount] = m.group()

        if m is None:
            result = re.compile(r'{"id":\d+,"jsonrpc":"\d.\d","error":(.+)}}', re.IGNORECASE)
            m = result.match(str(pkt.unknown_header))
            if m:
                if src not in self.httpMalformedHeaders:
                    self.httpMalformedHeaders[src] = {"login" : {}, "job" : {}, "keepalived" : {}, "submit" : {}, "error" : {self.packetCount : m.group()}}
                else:
                    self.httpMalformedHeaders[src]["error"][self.packetCount] = m.group()
        return
    #endregion

    #region TLS Checking
    def packet_tls(self, pkt):
        if self.tlsversion[pkt.record_version] in self.tls:
            self.tls[self.tlsversion[pkt.record_version]] += 1
        else:
            self.tls[self.tlsversion[pkt.record_version]] = 1
        return
    #endregion

    #region Data-Text-Line Checker
    def packet_data_text_line(self, pkt, uri):
        info = []
        for field_line in pkt._get_all_field_lines():
            info.append(field_line.strip().replace('\\r', '').replace('\\n', ''))
        self.httpInfo[uri]["Data-Text-Line"].append(info)
        return
    #endregion

    #region Protcol Checking
    def check_protocol(self, layerName):
        if layerName in self.protocols:
            self.protocols[layerName] += 1
        else:
            self.protocols[layerName] = 1
        return
    #endregion

    #region Set Collected Name 
    def set_name(self, name):
        self.captureName = name
        return
    #endregion

    #region Get Collected Name Retruns String
    def get_name(self):
        return self.captureName
    #endregion

    #region Get Collected Name Retruns String
    def get_namestripped(self):
        return self.captureName.split('.')[0]
    #endregion

    #region Get HTTP Information Returns Dictionary
    def getHttpInfo(self):
        return self.httpInfo
    #endregion

    #region Get HTTP Malformed Headers Returns Dictionary
    def getHttpMalformedHeaders(self):
        return self.httpMalformedHeaders
    #endregion

    #region Get Total UDP Count Returns Int
    def totalUDP(self):
        return self.udp
    #endregion

    #region Get Total TCP Count Returns Int
    def totalTCP(self):
        return self.tcp
    #endregion

    #region Get Total LLC Count Returns Int
    def totalLLC(self):
        return self.llc
    #endregion

    #region Get Total Other Protocol Count Returns Int
    def totalOTHER(self):
        return self.other
    #endregion
    
    #region Get SSL/TLS Returns Dictionary
    def ssltls(self):
        return self.tls
    #endregion

    #region Get All Protocols Returns Dictionary
    def all_protocols(self):
        return self.protocols
    #endregion

    #region Get Packet Count Returns Int
    def packet_count(self):
        return self.packetCount
    #endregion

    #region Get Packet Layer Count
    def packet_layer_count(self):
        return self.packetLayerCount
    #endregion

    #region Get IP Addresses Returns Dictionary
    def ip_addresses(self):
        return self.ipAddresses
    #endregion

    #region Get Filtered Protocols Returns Dictionary
    def filtered_protocols(self):
        self.lDict = {"TCP" : {}, "UDP" : {}, "LLC" : {}, "OTHER" : {} }
        self.udp = 0
        self.other = 0
        self.llc = 0
        self.tcp = 0
        for pkt in self.protocols:
            if pkt in self.udpList:
                if pkt in self.lDict["UDP"]:
                    self.lDict["UDP"][pkt] += self.protocols[pkt]
                else:
                    self.lDict["UDP"][pkt] = self.protocols[pkt]
                self.udp += self.protocols[pkt]

            elif pkt in self.tcpList:
                if pkt in self.lDict["TCP"]:
                    self.lDict["TCP"][pkt] += self.protocols[pkt]
                else:
                    self.lDict["TCP"][pkt] = self.protocols[pkt]
                self.tcp += self.protocols[pkt]

            elif pkt in self.llcList:
                if pkt in self.lDict["LLC"]:
                    self.lDict["LLC"][pkt] += self.protocols[pkt]
                else:
                    self.lDict["LLC"][pkt] = self.protocols[pkt]
                self.llc += self.protocols[pkt]

            else:
                if pkt in self.lDict["OTHER"]:
                    self.lDict["OTHER"][pkt] += self.protocols[pkt]
                else:
                    self.lDict["OTHER"][pkt] = self.protocols[pkt]
                self.other += self.protocols[pkt]

        return self.lDict
    #endregion

    #region Get IP Addresses Only Returns Array
    def ip_addresses_only(self):
        ipList = []
        for k in self.ipAddresses.keys():
            try:
                ips = k.split(" -> ")
                if ips[0] != '':
                    if ips[0] not in ipList:
                        ipList.append(ips[0])
                if ips[1] == '':
                    if ips[1] not in ipList:
                        ipList.append(ips[1])
            except:
                pass
        return ipList
    #endregion

    #region Get Filtered IP Addresses Returns Dictionary
    def ip_addresses_filtered(self):
        newDict = {}

        for k in self.ipAddresses.items():
            newDict[k[0]] = k[1]
            kSplit = k[0].split(" -> ")
            rev = kSplit[-1] + " -> " + kSplit[0]
        return newDict
    #endregion

    #region Get FQDN Returns Dictionary
    def fqdn(self):
        if not self.ip_fqdn:
            for snt in self.ip_addresses_only():
                ip = ipaddress.IPv4Address(snt)

                if ip.is_private is True:
                    self.ip_fqdn[snt] = "Local"
                else: 
                    dn = socket.getfqdn(snt)
                    if dn is snt:
                        self.ip_fqdn[snt] = "Not Found"
                    else: 
                        self.ip_fqdn[snt] = dn
        return self.ip_fqdn
    #endregion
