import os
import platform
import colorama 
from colorama import Fore, Back, Style

class FolderStruct:
    #region Init For Class
    def __init__(self, path):
        self.path = path
        self.folders = ["\\Reports"]
        return
    #endregion

    #region Check Folders
    def Check_Folders(self):
        for f in self.folders:
            path = self.path + f
            if platform.system() != "windows":
                path = path.replace("\\", "/")

            if not os.path.exists(path):
                os.makedirs(path)
                print(Fore.RED + "\t\t[!] " + Style.RESET_ALL + "Creating Folder")
            else:
                print(Fore.LIGHTGREEN_EX + "\t\t[-] " + Style.RESET_ALL + "All folders are present")
        return
    #endregion

    #region Check For Report Folder
    def Create_Report_Folder(self, name):
        path = self.path + self.folders[0] + "\\" + name + "\\"
        if platform.system() != "windows":
                path = path.replace("\\", "/")
        self.path = path
        if not os.path.exists(self.path):
            os.makedirs(self.path)
            print(Fore.RED + "\n\t[!] " + Style.RESET_ALL + "Creating Report Subfolder: " + name + "\n")
        else:
            print(Fore.LIGHTGREEN_EX + "\t\t[-] " + Style.RESET_ALL + "Report Subfolder Is Present : " + Fore.LIGHTYELLOW_EX + name + "\n" + Style.RESET_ALL) 
        return
    #endregion

    #region Get Path
    def Get_Path(self):
        return self.path + "\\"
    #endregion
