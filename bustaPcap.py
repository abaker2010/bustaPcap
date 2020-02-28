# Created by: Aaron Baker&Elliot Kjerstad
#region imports
import pyshark
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

#region custom classes
from application.classes.Configuration.Configuration import Configuration
from application.classes.BustaPcap import BustaPcap
from application.classes.Legal.Legal import Legal
from application.classes.Banners.BustaPcapBanner import BustaPcapBanner
from application.classes.Helpers.ScreenHelper import ScreenHelper
from application.classes.Helpers.Print import Print

        
try:
    import readline
except ImportError:
    sys.stdout.write("No readline module found, no tab completion available.\n")
else:
    import rlcompleter
    readline.parse_and_bind('tab: complete')
#endregion

#endregion

#region Usage
def Usage():
    parser.print_help()
    return
#endregion

def Agreement(config):
    """Legal agreement the at the user must accept to use the program"""
    while not config.getboolean("bustaPcap", "agreement"):
        ScreenHelper().clearScr()
        BustaPcapBanner().Banner()
        Legal().termsAndConditions()
        agree = input(Fore.LIGHTGREEN_EX + "\t\tYou must agree to our terms and conditions first (Y/n) " + Style.RESET_ALL).lower()
        if agree in config.get('bustaPcap', 'yes').split():
            config.set('bustaPcap', 'agreement', 'true')
            ScreenHelper().clearScr()
            BustaPcapBanner().Banner()

#region Main named if for keyboard interrupt
if __name__ == '__main__':
    try:
        colorama.init()
        BustaPcapBanner().Banner()
        conf = Configuration()
        Agreement(conf.Config())
        BustaPcap(conf).cmdloop()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\t[!] Forced Termination!! " + Style.RESET_ALL)
        exit()
    except Exception as e:
        print(e)
    finally:        
        exit()
#endregion