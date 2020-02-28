#region Import
import sys
import os
import time
import cmd
import platform
import pyshark
import multiprocessing
import configparser
from pathlib import Path
import colorama 
from colorama import Fore, Back, Style
from .Collector import Collector
from application.classes.Helpers.Print import Print
from application.classes.Helpers.PrinterBase import PrinterBase
from application.classes.Helpers.Saver import Saver
from application.classes.Helpers.Opener import FolderOpener
from application.classes.Structure.FolderStruct import FolderStruct
from application.classes.Helpers.ScreenHelper import ScreenHelper

class SinglePcap(cmd.Cmd):
    def __init__(self, configuration):
        cmd.Cmd.__init__(self,completekey='tab', stdin=None, stdout=None)
        self.config = configuration
        self.configObject = configuration.Config()
        self.prompt = Fore.LIGHTGREEN_EX + 'bustaPcap [' + Fore.LIGHTYELLOW_EX + 'pcap' + Fore.LIGHTGREEN_EX + '] > ' + Style.RESET_ALL
        self.doc_header = 'Commands'
        self.misc_header = 'System'
        self.undoc_header = 'Other'
        self.ruler = '-'
        self.pcap = None
        self.fqdn = False
        self.verbose = False
        self.reports = self.configObject.get('bustaPcap', 'reports')
        self.totals = self.configObject.get('bustaPcap', 'totals')
        self.printerBase = PrinterBase()

    def do_exit(self, line):
        self.config.Save()
        ScreenHelper().clearScr()
        return True

    def _options(self, fromShow):
        print(Fore.LIGHTGREEN_EX)
        print("\tPCAP: " + Fore.LIGHTYELLOW_EX + str(self.pcap) + Fore.LIGHTGREEN_EX)
        print("\tREPORTS: " + Fore.LIGHTYELLOW_EX + str(self.reports) + Fore.LIGHTGREEN_EX)
        print("\tTOTALS: " + Fore.LIGHTYELLOW_EX + str(self.totals) + Fore.LIGHTGREEN_EX)
        print("\tFQDN: " + Fore.LIGHTYELLOW_EX + str(self.fqdn) + Fore.LIGHTGREEN_EX)
        print("\tVERBOSE: " + Fore.LIGHTYELLOW_EX + str(self.verbose) + Fore.LIGHTGREEN_EX)
        print("\n\t" + ('-' * 20) + "\n")
        if fromShow:
            print("\tPlease use `show options` for more information")
        else:
            print("\tPCAP:" + Fore.LIGHTYELLOW_EX + "\t\tLocation of the PCAP file")
            print("\t\t\tAllowed file extentions: " + Fore.LIGHTGREEN_EX + "cap, pcap, pcapng\n")
            print("\tREPORTS:" + Fore.LIGHTYELLOW_EX + "\tLocation for output of report(s)\n" + Fore.LIGHTGREEN_EX)
            print("\tFQDN:" + Fore.LIGHTYELLOW_EX + "\t\tIP -> Fully Qualified Domain Name\n" + Fore.LIGHTGREEN_EX)
            print("\tVERBOSE:" + Fore.LIGHTYELLOW_EX + "\tSee detailed output of the pcap" + Fore.LIGHTGREEN_EX)

        print(Style.RESET_ALL)

    def _busta(self):
        try:
            print("")
            pcapFile = pyshark.FileCapture(self.pcap) # open PCAP
            self.printerBase.print_formatted_sub_header("Processing", optionaltext=os.path.basename(self.pcap).split('.')[0], tabs=1, ending="\n\n")
            collected = Collector(pcapFile, os.path.basename(self.pcap))
            print("\n")
            try:
                Saver(collected, self.fqdn).Save()
            except Exception as e:
                print("Error saving file: {0}".format(e))
            print("\n")
            
            collectedPrinter = Print(collected, self.fqdn, self.verbose)
            collectedPrinter.print_formatted_header(f"Data Processed From Pcap", headerColor=Fore.MAGENTA)
            collectedPrinter.Print_All()
            
            print("\n\n" + Fore.LIGHTGREEN_EX + "\tFull report saved to : {0}\n".format(FolderOpener().reports, self.totals))
            print(Fore.LIGHTGREEN_EX + "\tEasy access to reports use `open reports`" + Style.RESET_ALL, end="\n\n")
            
            pcapFile.close() # close PCAP
        except Exception as e:
            print("Error parsing pcap file: {0}".format(e))
            pcapFile.close()

    def do_busta(self, line):
        "\n\tAnalyze pcap file\n"

        try:
            if self.pcap == None:
                raise
            else:
                self._busta()
        except:
            print(Fore.LIGHTRED_EX + "\n\tERROR: Please check the options: `show options`\n" + Style.RESET_ALL)

    def do_open(self, line):
        "\n\tOpen Reports or Totals folder in browser\n"
        if line.lower() == "reports":
            FolderOpener().open_reports()
        elif line.lower() == "totals":
            FolderOpener().open_totals()
        else:
            print("\n" + Fore.LIGHTGREEN_EX)
            print("\tPlease use either Reports or Totals to be opened\n" + Style.RESET_ALL)
        
    
    def do_set(self, line):
        "\n\tSet parameter, use the `show` command to see parameters\n"
        params = line.split(' ')
        if not params[0]:
            print("\nPlease use the `show` command to see options that need set\n")
        elif params[0].lower() == "pcap" or params[0].lower() == "cap" or params[0] == "pcapng":
            try:
                if params[1] != None:
                    self.pcap = params[1]
                else:
                    raise
            except:
                print("Please add a pcap file")
        elif params[0].lower() == "verbose":
            try:
                if params[1].lower() == "true":
                    self.verbose = True
                elif params[1].lower() == "false":
                    self.verbose = False
                else:
                    raise
            except:
                print(Fore.LIGHTRED_EX + "\n\tMust be a boolean value\n" + Style.RESET_ALL)
        elif params[0].lower() == "fqdn":
            try:
                if params[1].lower() == "true":
                    self.fqdn = True
                elif params[1].lower() == "false":
                    self.fqdn = False
                else:
                    raise
            except:
                print(Fore.LIGHTRED_EX + "\n\tMust be a boolean value\n" + Style.RESET_ALL)

    def do_show(self, line):
        "\n\tShows configuration options. Please use `show` for more information\n"
        params = line.split(' ')
        if not params[0]:
            self._options(True)
        elif params[0].lower() == "options":
            self._options(False)
        else:
            print(Fore.LIGHTRED_EX + "\n\tInvaild Command\n" + Style.RESET_ALL)

