#region Import
import sys
import os
import time
import cmd
import platform
import pyshark
import threading
import configparser
from pathlib import Path
import queue
import time
import colorama 
from colorama import Fore, Back, Style
from application.classes.Helpers.Totals import Totals
from application.classes.Helpers.Print import Print
from application.classes.Helpers.PrinterBase import PrinterBase
from application.classes.Helpers.Saver import Saver
from application.classes.Collectors.Collector import Collector
from application.classes.Helpers.Opener import FolderOpener
from application.classes.Helpers.ScreenHelper import ScreenHelper

#endregion

class DirPcap(cmd.Cmd):
    def __init__(self, configuration):
        cmd.Cmd.__init__(self,completekey='tab', stdin=None, stdout=None)
        self.config = configuration
        self.configObject = configuration.Config()
        self.prompt = Fore.LIGHTGREEN_EX + 'bustaPcap [' + Fore.LIGHTYELLOW_EX + 'dir' + Fore.LIGHTGREEN_EX + '] > ' + Style.RESET_ALL
        self.doc_header = 'Commands'
        self.misc_header = 'System'
        self.undoc_header = 'Other'
        self.ruler = '-'
        self.fqdn = False
        self.verbose = False
        self.pcapdirectory = None
        self.reports = self.configObject.get('bustaPcap', 'reports')
        self.totals = self.configObject.get('bustaPcap', 'totals')
        self.extentions = self.configObject.get('bustaPcap', 'extentions')
        self.totalCollected = Totals()
        self.printerBase = PrinterBase()

    def do_exit(self, line):
        self.config.Save()
        ScreenHelper().clearScr()
        return True

    def _options(self, fromShow):
        print(Fore.LIGHTGREEN_EX)
        print("\tDIR: " + Fore.LIGHTYELLOW_EX + str(self.pcapdirectory) + Fore.LIGHTGREEN_EX)
        print("\tREPORTS: " + Fore.LIGHTYELLOW_EX + str(self.reports) + Fore.LIGHTGREEN_EX)
        print("\tTOTALS: " + Fore.LIGHTYELLOW_EX + str(self.totals) + Fore.LIGHTGREEN_EX)
        print("\tFQDN: " + Fore.LIGHTYELLOW_EX + str(self.fqdn) + Fore.LIGHTGREEN_EX)
        print("\tVERBOSE: " + Fore.LIGHTYELLOW_EX + str(self.verbose) + Fore.LIGHTGREEN_EX)
        print("\n\t" + ('-' * 20) + "\n")
        if fromShow:
            print("\tPlease use `show options` for more information")
        else:
            print("\tDIR:" + Fore.LIGHTYELLOW_EX + "\t\tLocation of the PCAP folder to use")
            print("\t\t\tAllowed file extentions: " + Fore.LIGHTGREEN_EX + "cap, pcap, pcapng\n")
            print("\tREPORTS:" + Fore.LIGHTYELLOW_EX + "\tLocation for output of report(s)\n" + Fore.LIGHTGREEN_EX)
            print("\tFQDN:" + Fore.LIGHTYELLOW_EX + "\t\tIP -> Fully Qualified Domain Name\n" + Fore.LIGHTGREEN_EX)
            print("\tVERBOSE:" + Fore.LIGHTYELLOW_EX + "\tSee detailed output of the pcap" + Fore.LIGHTGREEN_EX)

        print(Style.RESET_ALL)

    def do_set(self, line):
        "\n\tSet parameter, use the `show` command to see parameters\n"
        params = line.split(' ')
        if not params[0]:
            print("\nPlease use the `show` command to see options that need set\n")
        elif params[0].lower() == "dir" or params[0].lower() == "cap" or params[0] == "pcapng":
            try:
                if params[1] != None:
                    self.pcapdirectory = params[1]
                else:
                    raise
            except:
                print("Please add a pcap directory")
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

    #region recursivly collect files
    def _collectPcaps(self, folders, files):
        _folders = []
        _files = files[:]
        if len(folders) != 0:
            for folder in folders:
                try:
                    for entry in os.scandir(folder):
                        if entry.is_dir():
                            _folders.append(entry.path)
                        elif entry.is_file():
                            if entry.path.endswith(tuple(self.extentions)):
                                _files.append(entry.path)
                except Exception as e:
                    print(e)
            
            return self._collectPcaps(_folders, _files)
        else:
            return _files
    #endregion

    def do_open(self, line):
        "\n\tOpen Reports or Totals folder in browser\n"
        if line.lower() == "reports":
            FolderOpener().open_reports()
        elif line.lower() == "totals":
            FolderOpener().open_totals()
        else:
            print("\n" + Fore.LIGHTGREEN_EX)
            print("\tPlease use either Reports or Totals to be opened\n" + Style.RESET_ALL)

    def do_busta(self, line):
        "\n\tAnalyze pcap folder\n"

        _totals = Totals()

        try:
            if self.pcapdirectory == None:
                raise
            else:
                folders = []
                files = []
                correct_path = Path(Path(self.pcapdirectory))

                for entry in os.scandir(correct_path):
                    if entry.is_dir():
                        folders.append(entry.path)
                    elif entry.is_file():
                        if entry.path.endswith(tuple(self.extentions)):
                            files.append(entry.path)

                _files = self._collectPcaps(folders, files)

                self.printerBase.print_formatted_sub_header("Files to process", optionaltext=len(_files), tabs=1)

                try:
                    for f in _files:
                        self.printerBase.print_formatted_sub_header("Processing", optionaltext=f, tabs=1, ending="\n\n")

                        _pcapFile = pyshark.FileCapture(f)
                        collected = Collector(_pcapFile, os.path.basename(f))
                        print(f"\n")
                        try:
                            _totals.Add_Collector(collected)
                            # print(f"Totals: {_totals.Capture_Count()}")
                            # Saver(collected, self.fqdn).Save()
                            # Saver(collected, self.fqdn, FileName=collected.Get_Name(), Path=FolderOpener().totals + "/" + collected.Get_NameStripped() + "/").Save()
                        except Exception as e:
                            print("Error adding to totals: {0}".format(e))
                        print("\n")
                        _pcapFile.close()
                        self.printerBase.print_horizontal_break(hrColor=Fore.LIGHTRED_EX, ending="\n\n")

                except Exception as e:
                    print(e)

            totalsPrinter = Print(_totals, self.fqdn, self.verbose)
            totalsPrinter.print_formatted_header(f"Data Processed From Pcap", headerColor=Fore.MAGENTA)
            totalsPrinter.Print_All()
            print("\n")

        except Exception as e:
            print(e)
            print(Fore.LIGHTRED_EX + "\n\tERROR: Please check the options: `show options`\n" + Style.RESET_ALL)


    def do_show(self, line):
        "\n\tShows configuration options. Please use `show` for more information\n"
        params = line.split(' ')
        if not params[0]:
            self._options(True)
        elif params[0].lower() == "options":
            self._options(False)
        else:
            print(Fore.LIGHTRED_EX + "\n\tInvaild Command\n" + Style.RESET_ALL)

