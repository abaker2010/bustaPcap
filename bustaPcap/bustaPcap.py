# Created by: Aaron Baker&Elliot Kjerstad
import pyshark
import sys
import os
import time
import multiprocessing
from pathlib import Path
from optparse import OptionParser
import colorama 
from colorama import Fore, Back, Style

from classes.Collector import Collector
from classes.Print import Print
from classes.Totals import Totals
from classes.Writer import Writer
from classes.Saver import Saver
from classes.FolderStruct import FolderStruct

#region Option Parse
parser = OptionParser()

parser.add_option("-q", "--FQDN", dest="do_fqdn",
                  help="Usage: -q <FALSE|true>    This option finds Fully Qualified Domain Names with each IP found", default=False)

parser.add_option("-o", "--OUTPUT", dest="save_file",
                  help="Usage: -o <filename>    This option saves the output into the provided filename")

parser.add_option("-d", "--DIR", dest="dir_path",
                  help="Directory path that holds all PCAP files for parsing. Allowed files within are .pcap, .cap, .pcapng")

parser.add_option("-p", "--PCAP", dest="pcap_file",
                  help="PCAP File that will be parsed. Include whole destination path: Allowed file types are: .pcap, .cap, .pcapng")

parser.add_option("-v", "--VERBOSE", dest="verbose",
                  help="Verbose setting allowing for optional printing to screen", default=False)

options, args = parser.parse_args()
#endregion

#region Usage
def Usage():
    parser.print_help()
    return
#endregion

#region Print Title
def Print_Title():
    print(Fore.LIGHTGREEN_EX + "\n\t:::::::::  :::    :::  :::::::: ::::::::::: :::     :::::::::   ::::::::      :::     :::::::::")
    print("\t:+:    :+: :+:    :+: :+:    :+:    :+:   :+: :+:   :+:    :+: :+:    :+:   :+: :+:   :+:    :+:")
    print("\t+:+    +:+ +:+    +:+ +:+           +:+  +:+   +:+  +:+    +:+ +:+         +:+   +:+  +:+    +:+")
    print("\t+#++:++#+  +#+    +:+ +#++:++#++    +#+ +#++:++#++: +#++:++#+  +#+        +#++:++#++: +#++:++#+")
    print("\t+#+    +#+ +#+    +#+        +#+    +#+ +#+     +#+ +#+        +#+        +#+     +#+ +#+")
    print("\t#+#    #+# #+#    #+# #+#    #+#    #+# #+#     #+# #+#        #+#    #+# #+#     #+# #+#")
    print("\t#########   ########   ########     ### ###     ### ###         ########  ###     ### ###\n")
    print("\n\t================================================================================================")
    print("\t=                                       Zedo  &  Moose                                         =")
    print("\t================================================================================================\n\n" + Style.RESET_ALL)
    return
#endregion

#region Arg Checker
def Arg_Check():
    if options.pcap_file:
        if not options.pcap_file.endswith('.pcap') | options.pcap_file.endswith('.cap') | options.pcap_file.endswith('.pcapng'):
            print(Fore.RED + "\t[!] " + Style.RESET_ALL + "File type is not correct")
            print(Fore.YELLOW + "\t[-] " + Style.RESET_ALL + "Allowed file types are: .pcap, .cap, .pcapng")
            exit()

    if options.dir_path:
        dir = options.dir_path
        if not os.path.isdir(dir):
            print(Fore.RED + "\t[!] " + Style.RESET_ALL + "Directory path is not correct")
            exit()

    if options.do_fqdn:
        if options.do_fqdn.lower() == "true":
            options.do_fqdn = True
        elif options.do_fqdn.lower() == "false":
            options.do_fqdn = False
        else:
            print(Fore.RED + "\t[!] " + Stlye.RESET_ALL + "Invalid -q option! Accepts True or False")
            exit()

    if options.verbose:
        if options.verbose.lower() == "true":
            options.verbose = True
        elif options.verbose.lower() == "false":
            options.verbose = False
        else:
            print(Fore.RED + "\t[!] " + Stlye.RESET_ALL + "Invalid -v option! Accepts True or False")
            exit()

    if not options.pcap_file and not options.dir_path:
        print(Fore.RED + "\t[!] " + Style.RESET_ALL + "Please use -p <pcap> or -d <directory>")
        exit()
    return
#endregion

#region Check Folders
def Check_Folders():
    print(Fore.LIGHTGREEN_EX + "\t[-] " + Style.RESET_ALL + "Checking Folders")
    folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
    folders.Check_Folders()
    return
#endregion

#region Single PCAP
def Single_PCAP():
    now = time.time()
    
    captures = pyshark.FileCapture(options.pcap_file)
    folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
    folders.Create_Report_Folder((os.path.basename(options.pcap_file)).split('.')[0])
    capture = Collector(captures, FileName=(os.path.basename(options.pcap_file)), FolderName = os.path.dirname(os.path.abspath(__file__))).Rake()
    #caps = Print(capture, options.do_fqdn)
    
    if bool(options.verbose) is True:
        Print(capture, options.do_fqdn).Print_All()    
    
    print(Fore.LIGHTCYAN_EX + "\n\t  [?] " + Style.RESET_ALL + "Total Time Spent: " + Fore.LIGHTYELLOW_EX + "{0:.2f}".format(time.time() - now) + " seconds.." + Style.RESET_ALL)

    if options.save_file:
        return capture
    else:
        return None
#endregion

#region Directory PCAP
def Dir_PCAPS():
    folders = []
    files = []

    dir = Path(options.dir_path)
    correct_path = Path(dir)

    for entry in os.scandir(correct_path):
            if entry.is_dir():
                folder.append(entry.path)
            elif entry.is_file():
                files.append(entry.path)

    total_collection = Totals()
    totaltime = time.time()
    now = time.time()
    print(Fore.GREEN + "\n\t[+] " + Style.RESET_ALL + "Initializing Dictionary\n")

    for pcap in files:
        now = time.time()
        captures = pyshark.FileCapture(pcap)
        file = os.path.basename(pcap)
        print(Fore.LIGHTGREEN_EX + "\n\tProcessing File: " + Fore.LIGHTYELLOW_EX + file + Style.RESET_ALL)
        capture = Collector(captures, FileName=file, FolderName = os.path.dirname(os.path.abspath(__file__))).Rake()
        total_collection.Add_Collector(capture)
        print(Fore.LIGHTCYAN_EX + "\n\t  [?] " + Style.RESET_ALL + "Time Spent: " + Fore.LIGHTYELLOW_EX + "{0:.2f}".format(time.time() - now) + " seconds.." + Style.RESET_ALL)
    
    if bool(options.verbose) is True:
        Print(total_collection, options.do_fqdn).Print_All()

    print(Fore.LIGHTCYAN_EX + "\t  [?] " + Style.RESET_ALL + "Total Time Spent: " + Fore.LIGHTYELLOW_EX + "{0:.2f}".format(time.time() - totaltime) + " seconds.." + Style.RESET_ALL)

    if options.save_file:
        return total_collection
    else:
        return None
#endregion

#region Main
def Main():
    colorama.init()
    Arg_Check()
    Print_Title()
    Check_Folders()

    print(Fore.LIGHTGREEN_EX + "\n\t[-] " + Style.RESET_ALL + "Processing file(s). Please Wait...")
    if options.dir_path:
        collected = Dir_PCAPS()
    else:
        collected = Single_PCAP()

    if collected is not None:
        print(Fore.GREEN + "\n\t[-] " + Fore.LIGHTYELLOW_EX + "Writing to file" + Style.RESET_ALL)
        print(Fore.LIGHTGREEN_EX + "\t-----------------" + Style.RESET_ALL)
        if type(collected) is Totals:
            folder = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
            for pkt in collected.All_Collected():
                folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
                folders.Create_Report_Folder(pkt.Get_Name().split('.')[0])
                print("\t\t- %s : %s" % ("Saving data from", pkt.Get_Name()))
                Saver(pkt, options.do_fqdn, FileName=pkt.Get_Name().split('.')[0], Folders=folders, Path=folders.Get_Path()).Save()
            fileWriter = Writer(options.save_file, Saver(collected, options.do_fqdn), "a", path = folder.Get_Path())
            fileWriter.Save_Totals()
        else:
            folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
            folders.Create_Report_Folder(collected.Get_Name().split('.')[0])
            Saver(collected, options.do_fqdn, FileName=options.save_file, Folders=folders, Path=folders.Get_Path()).Save()
    return
#endregion

#region Main named if for keyboard interrupt
if __name__ == "__main__":
    try:
        Main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\t[!] Forced Termination!! " + Style.RESET_ALL)
        exit()
    except Exception as e:
        print(e)
    finally:
        exit()
#endregion