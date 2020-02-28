import sys
import os
import time
import cmd
import platform
import pyshark
import multiprocessing
import configparser
from pathlib import Path
import colorama 

class FolderOpener():
    """Open reports and totals folders."""
    def __init__(self):
        self.path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.reports = os.path.realpath(os.path.join(self.path, "Reports"))
        self.totals = os.path.realpath(os.path.join(self.path, "Totals"))

    def open_reports(self):
        try:
            os.system(f'open {self.reports}')
        except Exception as e:
            print(e)
            print("Error opening reports. Please make sure that the folders exist: `checkfolders`")


    def open_totals(self):
        try:
            os.system(f'open {self.totals}')
        except Exception as e:
            print("Error opening reports. Please make sure that the folders exist: `checkfolders`")