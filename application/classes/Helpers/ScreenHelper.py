#region imports
import sys
import os
import time
import platform
#endregion

class ScreenHelper():
    def __init__(self):
        return

    def clearScr(self):
        if platform.system() == "windows":
            os.system('cls')
        else:
            os.system('clear')