
import sys
import colorama
from colorama import Fore, Back, Style

class PrinterBase:
    def __init__(self):
        return
    
    def print_formatted_header(self, text, optionaltext="", tabs=1, vtabs=0, starting="\n", headerColor=Fore.LIGHTGREEN_EX):
        print(("\v" * vtabs) + starting + headerColor + ("\t" * tabs) + " " + text + Fore.LIGHTYELLOW_EX + f" {optionaltext}" + Style.RESET_ALL)
        print(headerColor + ("\t" * tabs) + ("-" * (len(text + f" {optionaltext}") + 2)) + Style.RESET_ALL, end="\n")


    def print_formatted_sub_header(self, text, leading="[-]", optionaltext="", tabs=2, vtabs=0, starting="\n", ending="\n"):
        print(("\v" * vtabs) + starting + Fore.LIGHTGREEN_EX + ("\t" * tabs) + f" {leading} " + Fore.LIGHTYELLOW_EX + text + Fore.LIGHTGREEN_EX + f" {optionaltext}" + Style.RESET_ALL)
        print(Fore.GREEN + ("\t" * tabs) + ("-" * (len(f" {leading} " + text + f" {optionaltext}") + 1)) + Style.RESET_ALL, end=ending)

    def print_formatted_body_item(self, text, leading="", optionaltext="", tabs=3, vtabs=0, starting=""):
        print(("\v" * vtabs) + Fore.LIGHTGREEN_EX + starting + ("\t" * tabs) + f"{leading}" + Fore.LIGHTYELLOW_EX + text + Fore.LIGHTGREEN_EX + f" {optionaltext}" + Style.RESET_ALL)

    def print_formatted_information_item(self, packetcount, items={}, optionaltext="", tabs=3, vtabs=1):
        for k, v in items:
            print(("\n" * vtabs) + ("\t" * tabs) + " " + Fore.LIGHTYELLOW_EX + k)
            print(Fore.LIGHTGREEN_EX + ("\t" * tabs) + ("-" * (len(k) + 2)) + Style.RESET_ALL)
            print(("\t" * tabs) + "  "+ Fore.LIGHTGREEN_EX + "Percentage: " + Fore.LIGHTYELLOW_EX + f"{round((v / packetcount) * 100, 2)} %")
            print(("\t" * tabs) + "  " + Fore.LIGHTGREEN_EX + "     Count: " + Fore.LIGHTCYAN_EX + f"{v}")
            
    def print_horizontal_break(self, tabs=1, vtabs=0, rulersize=75, hrColor=Fore.LIGHTCYAN_EX, ending="\n"):
        print(("\v" * vtabs) + ("\t" * tabs) + hrColor + ('-' * rulersize) + Style.RESET_ALL, end=ending)
        
        
    