#region imports
import colorama 
from random import randint
import random
from colorama import Fore, Back, Style
from application.classes.Colors.BustaPcapColors import BustaPcapColors
from application.classes.Banners.BannerEnum import BannerEnum
#endregion

class BustaPcapBanner():
    def __init__(self):
        return

    def _randomColor(self):
        random = randint(0,11)
        return BustaPcapColors().randomColor(random)

    def Banner(self, rand=True):
        if rand == True:
            print(self._randomColor())
        else:
            print(BustaPcapColors().randomColor(0))

        banner = random.choice(range(0,8))
        print("{0}".format(BannerEnum().randomBanner(banner)))
        print("\n\t================================================================================================")
        print("\t=                                       Zedo  &  elliotKeen                                    =")
        print("\t================================================================================================\n\n" + Style.RESET_ALL)
        return