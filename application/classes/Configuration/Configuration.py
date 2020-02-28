import pyshark
import sys
import os
import time
import cmd
import platform
import multiprocessing
import configparser
from pathlib import Path
import colorama 
from colorama import Fore, Back, Style

class Configuration():

    def __init__(self):
        self.installationDir = os.path.dirname(os.path.abspath(__file__)) + '/'
        self.configFile = self.installationDir + "bustaPcap.cfg"
        self.configParser = configparser.RawConfigParser()
        self.currentConfig = None

    def Config(self):
        conf = configparser.RawConfigParser()
        conf.read(self.configFile)
        self.currentConfig = conf
        return self.currentConfig

    def Save(self):
        conf = configparser.RawConfigParser()
        with open(self.configFile, 'w') as configfile:
            self.currentConfig.write(configfile)
    