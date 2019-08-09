#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
from classes.Collector import Collector

class Totals:
    #region Init For Totals Class
    def __init__(self):
        self.captures = []
        self.tcp = 0
        self.udp = 0
        self.llc = 0
        self.other = 0
        return
    #endregion

    #region Add Item To Collector
    def Add_Collector(self, collection):
        self.captures.append(collection)
        return
    #endregion

    #region Get All Collected Items Returns Array
    def All_Collected(self):
        return self.captures
    #endregion

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
            pktcount += c.packet_count()
        return pktcount
    #endregion

    #region Get Captured Filtered Protocols Returns Dictionary
    def Capture_Filtered_Protocols(self):
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
    #endregion

    #region Get Captured TLS Returns Dictionary
    def Capture_TLS(self):
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
    def Capture_IP_Filtered(self):
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