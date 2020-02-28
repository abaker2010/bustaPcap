import colorama 
from colorama import Fore, Back, Style

class Legal():
    def termsAndConditions(self):
        print(Fore.LIGHTYELLOW_EX + '\n\tI shall not use bustaPcap to:')
        print('\t-----------------------------\n')
        print('\t\t(i) inspect or, display or distribute any content that')
        print('\t\t\tinfringes any trademark, trade secret, copyright or other proprietary')
        print('\t\t\tor intellectual property rights of any person or company; \n\n' + Style.RESET_ALL)

