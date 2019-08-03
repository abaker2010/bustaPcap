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

from classes.Print import Print
from classes.Collector import Collector
from classes.Totals import Totals
from classes.Writer import Writer
from classes.FolderStruct import FolderStruct

parser = OptionParser()

parser.add_option("-q", "--FQDN", dest="do_fqdn",
                  help="Usage: -q <FALSE|true>    This option finds Fully Qualified Domain Names with each IP found", default=False)

parser.add_option("-o", "--OUTPUT", dest="save_file",
                  help="Usage: -o <filename>    This option saves the output into the provided filename")

parser.add_option("-d", "--DIR", dest="dir_path",
                  help="Directory path that holds all PCAP files for parsing. Allowed files within are .pcap, .cap, .pcapng")

parser.add_option("-p", "--PCAP", dest="pcap_file",
                  help="PCAP File that will be parsed. Include whole destination path: Allowed file types are: .pcap, .cap, .pcapng")

options, args = parser.parse_args()

def Usage():
    parser.print_help()
    return

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

    if not options.pcap_file and not options.dir_path:
        print(Fore.RED + "\t[!] " + Style.RESET_ALL + "Please use -p <pcap> or -d <directory>")
        exit()
    return

def Check_Folders():
    print(Fore.LIGHTGREEN_EX + "\t[-] " + Style.RESET_ALL + "Checking Folders")
    folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
    folders.Check_Folders()
    return

def Single_PCAP():
    now = time.time()
    
    captures = pyshark.FileCapture(options.pcap_file)
    folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
    folders.Create_Report_Folder((os.path.basename(options.pcap_file)).split('.')[0])
    capture = Collector(captures, FileName=(os.path.basename(options.pcap_file)), FolderName = os.path.dirname(os.path.abspath(__file__)))
    caps = Print(capture, options.do_fqdn)
    caps.Print_All()
    
    print(Fore.LIGHTCYAN_EX + "\n\t\t[?] " + Style.RESET_ALL + "Total Time Spent: " + Fore.LIGHTYELLOW_EX + "{0:.2f}".format(time.time() - now) + " seconds.." + Style.RESET_ALL)

    if options.save_file:
        return caps
    else:
        return None

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
        capture = Collector(captures, FileName=file, FolderName = os.path.dirname(os.path.abspath(__file__)))
        total_collection.Add_Collector(capture)
        print(Fore.LIGHTCYAN_EX + "\n\t[?] " + Style.RESET_ALL + "Time Spent: " + Fore.LIGHTYELLOW_EX + "{0:.2f}".format(time.time() - now) + " seconds.." + Style.RESET_ALL)
        
    #Print(total_collection, options.do_fqdn).Print_All()
    print(Fore.LIGHTCYAN_EX + "\t[?] " + Style.RESET_ALL + "Total Time Spent: " + Fore.LIGHTYELLOW_EX + "{0:.2f}".format(time.time() - totaltime) + " seconds.." + Style.RESET_ALL)

    if options.save_file:
        return total_collection
    else:
        return None

def SaveCaptToFile(capt, folders):
    
    print(Fore.LIGHTGREEN_EX + "\t\t-------------------------------" + Style.RESET_ALL)
    #print("\t\t\t- %s : %s" % ("Saving data from", capt.collection.Get_Name()))
    saveIPFilters = Writer(options.save_file + "-Filtered-IPS", capt.Save_IPS_Filtered(), "w+", infoname = "Filtered IPS", path = folders.Get_Path())
    saveIPFilters.Save_Info()

    if options.do_fqdn is True:
        saveFQDN = Writer(options.save_file + "-IPS-FQDN", capt.Save_IPS_Filtered(), "w+", infoname = "IPs to FQDN", path = folders.Get_Path())
        saveFQDN.Save_Info()

    saveSSLTLS = Writer(options.save_file + "-SSL-TLS", capt.Save_SSLTLS(), "w+", infoname = "SSL/TLS", path = folders.Get_Path())
    saveSSLTLS.Save_Info()

    saveLLC = Writer(options.save_file + "-LLC", capt.Save_LLC(), "w+", infoname = "LLC", path = folders.Get_Path())
    saveLLC.Save_Info()

    saveTCP = Writer(options.save_file + "-TCP", capt.Save_TCP(), "w+", infoname = "TCP", path = folders.Get_Path())
    saveTCP.Save_Info()

    saveUDP = Writer(options.save_file + "-UDP", capt.Save_UDP(), "w+", infoname = "UDP", path = folders.Get_Path())
    saveUDP.Save_Info()

    saveOtherProtcols = Writer(options.save_file + "-Other-Protocols", capt.Save_Other_Protocols(), "w+", infoname = "Other Protocols", path = folders.Get_Path())
    saveOtherProtcols.Save_Info()

    saveHttpInfo = Writer(options.save_file + "-Http-Info", capt.Save_HttpInfo(), "w+", infoname = "HTTP Info", path = folders.Get_Path())
    saveHttpInfo.Save_Info()

    saveHttpMalformedHeaders = Writer(options.save_file + "-HTTP-Malformed-Headers", capt.Save_HttpMalformedHeaders(), "w+", infoname = "Http Malformed Headers", path = folders.Get_Path())
    saveHttpMalformedHeaders.Save_Info()

    fileWriter = Writer(options.save_file, capt, "w+", infoname = "All Data", path = folders.Get_Path())
    fileWriter.Save()
    return

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
            print(folder.Get_Path())
            for pkt in collected.All_Collected():
                folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
                folders.Create_Report_Folder(pkt.Get_Name().split('.')[0])
                print("\t\t- %s : %s" % ("Saving data from", pkt.Get_Name()))
                #fileWriter = Writer(options.save_file, Print(pkt, options.do_fqdn), "a")
                #fileWriter.Save()
                SaveCaptToFile(Print(pkt, options.do_fqdn), folders)
            fileWriter = Writer(options.save_file, Print(collected, options.do_fqdn), "a", path = folder.Get_Path())
            fileWriter.Save_Totals()
        else:
            folders = FolderStruct(os.path.dirname(os.path.abspath(__file__)))
            folders.Create_Report_Folder(collected.collection.Get_Name().split('.')[0])
            SaveCaptToFile(collected, folders)
    return

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