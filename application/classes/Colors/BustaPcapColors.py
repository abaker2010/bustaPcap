import colorama 
from colorama import Fore, Back, Style

class BustaPcapColors():
    def __init__(self):
        return

    def randomColor(self, number):
        # GREEN, RED, YELLOW, CYAN, BLUE, MAGENTA, WHITE
        if number == 0:
            return Fore.LIGHTGREEN_EX
        elif number == 1:
            return Fore.LIGHTRED_EX
        elif number == 2:
            return Fore.LIGHTCYAN_EX
        elif number == 3:
            return Fore.LIGHTBLUE_EX
        elif number == 4:
            return Fore.LIGHTMAGENTA_EX
        elif number == 5:
            return Fore.LIGHTYELLOW_EX
        elif number == 6:
            return Fore.GREEN
        elif number == 7:
            return Fore.RED
        elif number == 8:
            return Fore.CYAN
        elif number == 9:
            return Fore.BLUE
        elif number == 10:
            return Fore.MAGENTA
        elif number == 11:
            return Fore.YELLOW



    