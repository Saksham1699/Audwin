#!/usr/bin/python3

import msvcrt
import os
import sys
import subprocess
import win32file

from writer import writer

def quitter():

    msg = "Press any key to quit.\n"
    writer(msg)
    msvcrt.getch()
    os.system('cls')
    sys.exit(0)

def reponse():

    while True:
        rep = msvcrt.getch()
        if 'y' in str(rep):
            # print("machin ok")
            return 'y'
        elif 'n' in str(rep):
            return 'n'

def dismount(key):

    my_app = "RemoveDrive.exe"
    remover, _ = verif_prog(my_app, key)
    if remover != '':
        params = key + ' -L -b' 
        cmdline_user = my_app + ' ' + params
        directory = os.path.dirname(os.path.abspath(remover))
        # print("test : ",cmdline_user)
        # print("test directory : ",directory)
        subprocess.call(cmdline_user, cwd=directory, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        quitter()

def verif_prog(prog, key):
    
    prog_find = ''
    prog_find_path = ''
    compteur = -1

    
    prog_find, prog_find_path, compteur = find_that(prog, key)

    if compteur == -1:
        print("\nThis app needs " + str(prog) + " !")

    return prog_find, prog_find_path

def find_that(prog, folder):
    
    prog_find = ""
    prog_find_path = ""
    compteur = -1
    # print("Recherche dans => "+str(folder))
    folder = folder+"/"
    for root, _, filenames in os.walk(folder):
        for filename in filenames:
            # print("recherche de "+str(prog)+" dans "+str(folder))#"ok
            # print("filename :",filename)#ok
            if prog == filename:
                prog_find_path = os.path.abspath(root)
                # print("path prog :"+str(prog_find_path)) #test ok
                prog_find = os.path.abspath(root)+"/"+prog
                # root+"/"+prog
                # print (prog_find+" trouvé !\n") #ok
                compteur = 1
                return prog_find, prog_find_path, compteur
    return prog_find, prog_find_path, compteur

def amovible(key):
    return win32file.GetDriveType(key) == win32file.DRIVE_REMOVABLE
