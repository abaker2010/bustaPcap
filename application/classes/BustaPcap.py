#region Import
from .Structure.FolderStruct import FolderStruct
import sys
import os
import time
import cmd
import platform
import multiprocessing
import configparser
from pathlib import Path
import colorama 
from colorama import Fore, Back, Style
from .Legal.Legal import Legal
from .Collectors.SinglePcap import SinglePcap
from .Collectors.DirPcap import DirPcap
from application.classes.Banners.BustaPcapBanner import BustaPcapBanner
from application.classes.Helpers.Opener import FolderOpener
from application.classes.Helpers.ScreenHelper import ScreenHelper

#endregion

class BustaPcap(cmd.Cmd):
    def __init__(self, configuration):
        cmd.Cmd.__init__(self,completekey='tab', stdin=None, stdout=None)
        self.config = configuration
        self.prompt = Fore.LIGHTGREEN_EX + 'bustaPcap > ' + Style.RESET_ALL
        self.doc_header = Fore.LIGHTYELLOW_EX + 'Commands' + Style.RESET_ALL
        self.misc_header = Fore.LIGHTYELLOW_EX + 'System' + Style.RESET_ALL
        self.undoc_header = Fore.LIGHTYELLOW_EX + 'Other' + Style.RESET_ALL
        self.ruler = '-'

    #region Check Folders
    def Check_Folders(self):
        print(Fore.LIGHTGREEN_EX + "\n\t[-] " + Style.RESET_ALL + "Checking Folders")
        folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)), self.config.currentConfig.get('bustaPcap', 'verbose'))
        folders.Check_Folders()
        print("\n")
        return
    #endregion

    #region Other Section
    def do_legal(self, line):
        Legal().termsAndConditions()
        
    def do_exit(self, line):
        self.config.Save()
        return True
    
    # def do_clean(self, line):
    #     clean = input("Are you sure you want to clean the program? This will remove all old data. (Y/n) ").lower()
    #     if clean in self.config.currentConfig.get('bustaPcap', 'yes').split():
    #         print("Clean folders")
    #     else:
    #         self.do_clean(line)
    
    def do_banner(self, line):
        ScreenHelper().clearScr()
        BustaPcapBanner().Banner()
    #endregion
    
    # # Todo: this needs to un/install to the path of the system and update self from github
    # #region System
    # def do_install(self, line):
    #     print("install via sh")

    # def do_uninstall(self, line):
    #     print("uninstall via sh")

    # def do_update(self, line):
    #     print("update via github and sh")        
    # #endregion

    # def clearScr(self):
    #     if platform.system() == "windows":
    #         os.system('cls')
    #     else:
    #         os.system('clear')

    #region Commands
    def do_pcap(self, line):
        "\n\tProcess a sinlge pcap file\n"
        ScreenHelper().clearScr()
        SinglePcap(self.config).cmdloop()

    def do_dir(self, line):
        "\n\tProcess a directory of pcap files\n"
        ScreenHelper().clearScr()
        DirPcap(self.config).cmdloop()
        
    def do_checkfiles(self, line):
        "\n\tCheck needed structure for bustaPcap\n"
        self.Check_Folders()

    def do_open(self, line):
        "\n\tOpen Reports or Totals folder in browser\n"
        if line.lower() == "reports":
            FolderOpener().open_reports()
        elif line.lower() == "totals":
            FolderOpener().open_totals()
        else:
            print("\n" + Fore.LIGHTGREEN_EX)
            print("\tPlease use either Reports or Totals to be opened\n" + Style.RESET_ALL)
        
        
    def do_shell(self, line):
        "\n\tRun a shell command, becareful with this. This feature is still in beta\n"
        print("running shell command:", line)
        output = os.popen(line).read()
        print("\n{0}{1}{2}".format(Fore.LIGHTGREEN_EX,output, Style.RESET_ALL))
        self.last_output = output
    #endregion
