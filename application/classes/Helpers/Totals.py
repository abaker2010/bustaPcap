#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
from application.classes.Collectors.Collector import Collector

class Totals:
    #region Init For Totals Class
    def __init__(self):
        self.captures = []
        self.tcp = 0
        self.udp = 0
        self.llc = 0
        self.other = 0
        self.packetCount = 0
        self.packetLayerCount = 0

        self.protocols = {} 
        self.ipAddresses = {}
        self.tls = {}
        self.ip_fqdn = {}
        self.httpInfo = {}
        self.httpMalformedHeaders = {}

        self._filtered_protocols = None

        return
    #endregion

    #region Add Item To Collector
    def Add_Collector(self, collection):        
        self.captures.append(collection)
        try:
            # adding protocols
            self._add_to_dic(self.protocols, collection.all_protocols().items())
            # adding ip's
            self._add_to_dic(self.ipAddresses, collection.ip_addresses().items())
            # adding ssltls
            self._add_to_dic(self.tls, collection.ssltls().items())

            # adding tcp 
            self.tcp += collection.totalTCP()
            self.udp += collection.totalUDP()
            self.llc += collection.totalLLC()
            self.other += collection.totalOTHER()
            self.packetCount += collection.packet_count()
            self.packetLayerCount += collection.packet_layer_count()
            
            self.ip_fqdn.update(collection.fqdn())
            self.httpInfo.update(collection.getHttpInfo())
            self.httpMalformedHeaders.update(collection.getHttpMalformedHeaders())
        
        except Exception as e:
            print(e)
        return
    #endregion

    def _add_to_dic(self, dic, items):
        for k, v in items:
            try:
                dic[k] += v
            except:
                dic[k] = v
        return

    #region Get All Collected Items Returns Array
    def All_Collected(self):
        return self.captures
    #endregion

    def Get_HttpInfo(self):
        return self.httpInfo

    def Total_Packet_Layer_Count(self):
        return self.packetLayerCount

    def packet_count(self):
        return self.packetCount

    def Total_Protocols(self):
        return self.protocols

    def Total_IpAddresses(self):
        return self.ipAddresses

    def Total_SSLTlS(self):
        return self.tls

    #region Get Capture Count Returns Int
    def Capture_Count(self):
        return len(self.captures)
    #endregion

    #region Get Total TCP Count Returns Int
    def Total_TCP(self):
        return self.tcp
    #endregion

    #region Get Total UDP Count Returns Int
    def Total_UDP(self):
        return self.udp
    #endregion

    #region Total Other Protocol Count Returns Int
    def Total_Other(self):
        return self.other
    #endregion

    #region Get Total LLC Count Returns Int
    def Total_LLC(self):
        return self.llc
    #endregion

    #region Get Capture Total Count Returns Int
    def Capture_Total_Count(self):
        pktcount = 0
        for c in self.captures:
            print(isinstance(c, Collector))
            pktcount += c.packet_count()
        return pktcount
    #endregion

    #region Get Captured Filtered Protocols Returns Dictionary
    def filtered_protocols(self):
        if self._filtered_protocols is None:
            proTotal = {"TCP" : {}, "UDP" : {}, "LLC" : {}, "OTHER" : {} }
            for c in self.captures:
                proto = c.filtered_protocols()
                for t, v in proto["TCP"].items():
                    if t in proTotal["TCP"]:
                        proTotal["TCP"][t] += v
                    else:
                        proTotal["TCP"][t] = v
                    self.tcp += v

                for t, v in proto["UDP"].items():
                    if t in proTotal["UDP"]:
                        proTotal["UDP"][t] += v
                    else:
                        proTotal["UDP"][t] = v
                    self.udp += v

                for t, v in proto["LLC"].items():
                    if t in proTotal["LLC"]:
                        proTotal["LLC"][t] += v
                    else:
                        proTotal["LLC"][t] = v
                    self.llc += v

                for t, v in proto["OTHER"].items():
                    if t in proTotal["OTHER"]:
                        proTotal["OTHER"][t] += v
                    else:
                        proTotal["OTHER"][t] = v
                    self.other += v
            return proTotal
        else:
            return self._filtered_protocols

        
    #endregion

    #region Get Captured TLS Returns Dictionary
    def ssltls(self):
        tlsTotal = {}
        for c in self.captures:
            filtered = c.ssltls()
            for k, v in filtered.items():
                if k in tlsTotal:
                    tlsTotal[k] += v
                else:
                    tlsTotal[k] = v
        return tlsTotal
    #endregion

    #region Get Captured IPs Filtered Returns Dictionary
    def ip_addresses_filtered(self):
        ipDict = {}
        for c in self.captures:
            filtered = c.ip_addresses_filtered()
            for k, v in filtered.items():
                if k in ipDict:
                    ipDict[k] += v
                else:
                    ipDict[k] = v
        return ipDict
    #endregion 

    #region Capture IP FQDN Returns Dictionary
    def Capture_IP_FQDN(self):
        fqdnDict = {}
        for c in self.captures:
            ip = c.fqdn()
            for k, v in ip.items():
                if k not in fqdnDict:
                    fqdnDict[k] = v
        return fqdnDict
    #endregion