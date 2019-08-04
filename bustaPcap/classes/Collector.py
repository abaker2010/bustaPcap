#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
import sys
import os
import socket
import inspect
import platform
import re 
import colorama 
from colorama import Fore, Back, Style
from classes.Writer import Writer
from classes.FolderStruct import FolderStruct

class Collector:
    def __init__(self, capts, *args, **kwargs):
    #region Class Variables
        #region Passed
        self.captureName = kwargs.get("FileName", None)
        self.folderPath = kwargs.get("FolderName", None)
        self.capts = capts
        #endregion

        #region Numerical
        self.packetCount = 0
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
        #endregion

        #region Arrays
        self.llcList = ["llc", "stp", "dtp", "cdp"]
        self.udpList = ["udp", "ntp", "dns", "mdns", "ssdp", "browser", "nbns", "smb", "gquic", "dhcpv6"]
        self.tcpList = ["http", "tcp", "data-text-lines", "tls"]
        #endregion
    #endregion 


        for pkt in self.capts:
            self.packetCount += 1
            sys.stdout.write(Fore.LIGHTCYAN_EX + "\r\t[?] " + Style.RESET_ALL + "Packet Num : " + Fore.LIGHTYELLOW_EX + str(self.packetCount) + Style.RESET_ALL)
            uri = None
            try:
                src = pkt.ip.src + " -> " + pkt.ip.dst
                if src in self.ipAddresses:
                    self.ipAddresses[src] += 1
                else:
                    self.ipAddresses[src] = 1
            except:
                pass
            
            for p in pkt.layers:
                try:
                    layerName = None
                    if p._layer_name.lower() == "fake-field-wrapper":
                       layerName = p.layer_name
                    else:
                        layerName = p._layer_name
                        
                    if layerName == "tls":
                        try:
                            if self.tlsversion[p.record_version] in self.tls:
                                self.tls[self.tlsversion[p.record_version]] += 1
                            else:
                                self.tls[self.tlsversion[p.record_version]] = 1
                        except Exception as e:
                            pass
                    if layerName == "http":
                        info = {}
                        if hasattr(p, 'unknown_header') is True:
                            # wire shark is getting this mixed up with a bad header so that is why it is showing funny in the 
                            # program not their fault but is it because the coin miner is able to by pass firewalls and such this way
                            # In here needs to be regex parser try catchs for each one found then 
                            # have a dict like {Loging : {}, Job : {}, Error : {}}
                            # use the json to c# to build the needed objects that the logic will need

                            # in each instance this needs to add information to the httpinfo dict in the malform header section
                            # then when printing the malformed header needs to be checked and printed if there is any information to be displayed

                            result = re.compile(r'{"jsonrpc":"\d.\d","method":"(\w+)","params":{(.+)}}', re.IGNORECASE)
                            m = result.match(str(p.unknown_header))
                            if m:
                                # so far have only found 'job' for the method
                                if src not in self.httpMalformedHeaders:
                                    self.httpMalformedHeaders[src] = {"login" : {}, "job" : {self.packetCount : m.group()}, "keepalived" : {}, "submit" : {}, "error" : {}}
                                else:
                                    self.httpMalformedHeaders[src]["job"][self.packetCount] = m.group()

                            if m is None:
                                result = re.compile(r'{"id":\d+,"jsonrpc":"\d.\d","method":"(\w+)","params":{(.+)}}', re.IGNORECASE)
                                m = result.match(str(p.unknown_header))
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
                                m = result.match(str(p.unknown_header))
                                if m:
                                    if src not in self.httpMalformedHeaders:
                                        self.httpMalformedHeaders[src] = {"login" : {}, "job" : {}, "keepalived" : {}, "submit" : {}, "error" : {self.packetCount : m.group()}}
                                    else:
                                        self.httpMalformedHeaders[src]["error"][self.packetCount] = m.group()
                        for field_line in p._get_all_field_lines():
                            if ':' in field_line:
                                field_name, field_line = field_line.split(':', 1)
                                info[field_name.strip()] = field_line.strip().replace('\\r', '').replace('\\n', '')
                        if hasattr(p, 'response_code') is True:
                            if p.response_for_uri not in self.httpInfo:
                                self.httpInfo[p.response_for_uri] = { "IP" : src, "Sent" : [], "Recv" : [info], "Data-Text-Line" : []}
                            else: 
                                self.httpInfo[p.response_for_uri]["Recv"].append(info)
                            uri = p.response_for_uri
                        else: 
                            if p.request_full_uri not in self.httpInfo:
                                self.httpInfo[p.request_full_uri] = { "IP" : src, "Sent" : [info], "Recv" : [], "Data-Text-Line" : []}
                            else: 
                                self.httpInfo[p.request_full_uri]["Sent"].append(info)
                            uri = p.request_full_uri

                    if layerName == "data-text-lines":
                        info = []
                        for field_line in p._get_all_field_lines():
                            info.append(field_line.strip().replace('\\r', '').replace('\\n', ''))
                        self.httpInfo[uri]["Data-Text-Line"].append(info)

                    if layerName == "media":
                        dataString = ""
                        for d in p.type.split(':'):
                            dataString += str(bytes.fromhex(d), 'utf-8')
                        try:
                            folder = self.folderPath + "\\Reports\\" + self.captureName.split('.')[0] + "\\"
                            if platform.system() != "windows":
                                folder = folder.replace("\\", "/")  
                            fileSaver = Writer("Media-" + uri.replace('\\','-').replace('*','-').replace('?','-').replace('"','-').replace('<','-').replace('>','-').replace('/', '-').replace(':', '-').replace('|','-'), dataString, 'w', path = folder)
                            fileSaver.Save_Media()
                        except Exception as e:
                            print("Error setting folder path")
                            print(e)

                    if layerName in self.protocols:
                        self.protocols[layerName] += 1
                    else:
                        self.protocols[layerName] = 1
                except Exception as ex:
                    pass
            sys.stdout.flush()
        return
    
    #region Set Collected Name 
    def Set_Name(self, name):
        self.captureName = name
        return
    #endregion

    #region Get Collected Name Retruns String
    def Get_Name(self):
        return self.captureName
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
            ips = k.split(" -> ")
            if ips[0] not in ipList:
                ipList.append(ips[0])
            if ips[1] not in ipList:
                ipList.append(ips[1])
        return ipList
    #endregion

    #region Get Filtered IP Addresses Returns Dictionary
    def ip_addresses_filtered(self):
        newDict = {}
        for k in self.ipAddresses.keys():
            ips = k.split(" -> ")
            if k not in newDict:
                newDict[k] = self.ipAddresses[k]
                rev = ips[1] + " -> " + ips[0]
                try:
                    newDict[rev] = self.ipAddresses[rev]
                except:
                    newDict[rev] = 0
                pass
        return newDict
    #endregion

    #region Get FQDN Returns Dictionary
    def fqdn(self):
        if not self.ip_fqdn:
            for snt in self.ip_addresses_only():
                ips = snt.split(".")
                if ips[0] == "192":
                    self.ip_fqdn[snt] = "Local"
                else:
                    dn = socket.getfqdn(snt)
                    if dn is snt:
                        self.ip_fqdn[snt] = "Not Found"
                    else: 
                        self.ip_fqdn[snt] = dn
        return self.ip_fqdn
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

    #region Get IP Addresses Returns Dictionary
    def ip_addresses(self):
        return self.ipAddresses
    #endregion