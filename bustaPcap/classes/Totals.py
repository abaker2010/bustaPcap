#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad
from classes.Collector import Collector

class Totals:
    def __init__(self):
        self.captures = []
        self.tcp = 0
        self.udp = 0
        self.llc = 0
        self.other = 0
        return

    def Add_Collector(self, collection):
        self.captures.append(collection)
        return

    def All_Collected(self):
        return self.captures

    def Capture_Count(self):
        return len(self.captures)

    def Total_TCP(self):
        return self.tcp

    def Total_UDP(self):
        return self.udp

    def Total_Other(self):
        return self.other

    def Total_LLC(self):
        return self.llc

    def Capture_Total_Count(self):
        pktcount = 0
        for c in self.captures:
            pktcount += c.packet_count()
        return pktcount

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

    def Capture_IP_FQDN(self):
        fqdnDict = {}
        for c in self.captures:
            ip = c.fqdn()
            for k, v in ip.items():
                if k not in fqdnDict:
                    fqdnDict[k] = v
        return fqdnDict