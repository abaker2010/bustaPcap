#!/usr/bin/python
# Created by: Aaron Baker&Elliot Kjerstad

from pathlib import Path
import colorama 
import os
import platform
from colorama import Fore, Back, Style

class Writer():
    #region Init For Class
    def __init__(self, filename, data, mode, *args, **kwargs):
        self.filename = filename
        self.data = data
        self.mode = mode
        self.infoname = kwargs.get("infoname", None)
        self.foldername = kwargs.get("foldername", None)
        self.path = kwargs.get("path", None)
        return
    #endregion

    #region Save Totals For Printer Data
    def Save_Totals(self):
        with open(self.path + "\\Totals\\" + self.filename + "-Directory-Totals" + ".txt", self.mode) as file:
            try:
                file.write(str(self.data))
                file.write("\n\n")
            except Exception as e:
                print("Saving Error")
                print(e)
        return

    #region Save Printer Data
    def Save(self):
        # changes needed to be made so that if the file exists the file is deleted and then re-created
        with open(self.path + self.filename + "-All-Info" + ".txt", self.mode) as file:
            try:
                file.write(self.data)
                file.write("\n\n")
            except Exception as e:
                print("Saving Error")
                print(e)
        return
    #endregion

    #region Save Media
    def Save_Media(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        with open(self.path + self.filename, self.mode) as file:
            try:
                file.write(self.data)
            except Exception as e:
                print("Saving Media Error")
                print(self.mode)
                print(e)
        return
    #endregion

    #region Save JFIF
    def Save_JFIF(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        with open(self.path + self.filename, self.mode) as file:
            try:
                file.write(self.data)
                file.write("\n\n")
            except Exception as e:
                print("Saving Media Error")
                print(e)
        return
    #endregion

    #region Save Information self.data
    def Save_Info(self):
        print(Fore.LIGHTCYAN_EX + "\t\t\t[?] " + Style.RESET_ALL + "Saving data for : " + Fore.LIGHTYELLOW_EX + self.infoname + Style.RESET_ALL)
        # print(self.path)
        with open(self.path + self.filename + ".txt", self.mode) as file:
            try:
                file.write(self.data)
                file.write("\n\n")
            except Exception as e:
                print("Saving %s Error" % (self.infoname))
                print(e)
        return
    #endregion

