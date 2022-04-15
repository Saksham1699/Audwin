#!/usr/bin/python3
import os
import time
import webbrowser
from datetime import datetime

#Project modules imports
import writer
import verif
import scans
from software_scan import software_init
from complement import complement_init

COMPUTERNAME = os.environ['COMPUTERNAME']
STYLECSSFILE = os.getcwd() + '/style.css'

def scanpart():
    
    key = os.getcwd() 
    key = str(key[:2])
    return key

def scanpc(log_file_path):
    texte = "Computer scanning in progress... Please wait...\n"
    writer.writer(texte)

    log_file = str(log_file_path) + "FINAL.html"

    # Write first html tags
    elementraw = """<!DOCTYPE html>
    <html>
        <head>
            <title>ScanPC result</title>
            <meta charset="utf-8">
            <link rel="stylesheet" type="text/css" href="style.css">
        </head>
        <body>
            <p>
            {0}
            {1} <br>
            </p>"""
            # </body>
        # </html>"""

    texte = '<h1>Scanning of computer "' + COMPUTERNAME + '"</h1>'
    element2 = '<time>' + datetime.now().strftime("%A %d %B %Y %H:%M:%S") + '</time>\n'
    element = elementraw.format(texte, element2)
    writer.writelog(log_file, element)


    scans.user_info(log_file_path)
    scans.shared_folders_info(log_file_path)
    scans.hotfixes_info(log_file_path)
    scans.system_info(log_file_path)
    scans.security_product_info(log_file_path)
    scans.process_info(log_file_path)
    services_running_dict = scans.services_info(log_file_path)
    scans.ports_info(log_file_path)
    #scans.persistence_info(log_file_path)

    texte4 = "\nBasic scan ended.\n"
    writer.writer(texte4)

    software_dict = software_init(log_file_path)

    return log_file, software_dict, services_running_dict

#def readandcopy(log_file):
 #   msg0 = "\nDo you want to read the scan report ? (y = yes, n = no)\n"
  #  writer.writer(msg0)
   # if verif.reponse() == 'y':
    #    openers = webbrowser._tryorder
     #   opened = 0
      #  for browsers in openers:
       #     print(browsers)
         #   if 'firefox' in browsers.lower() or 'chrome' in browsers.lower():
        #        print('Opening with ' + browsers)
          #      browser = webbrowser.get(webbrowser._tryorder[openers.index(browsers)])
           #     browser.open('file:' + str(log_file))
            #    opened = 1
             #   break
        #if opened == 0:
         #   webbrowser.open(str(log_file))


    #msg0 = "\nDo you want a copy the scan report on the computer (C:\\ drive) ? (y = yes, n = no)\n"
    #writer.writer(msg0)
    #if verif.reponse() == 'y':
        # Copy log
     #   file_name = os.path.basename(log_file)
      #  file_to_write = "C:/" + file_name
       # writer.copy_file(log_file, file_to_write)
        # Copy CSS file
        #if os.path.isfile(STYLECSSFILE):
         #   file_name = os.path.basename(STYLECSSFILE)
          #  file_to_write = "C:/" + file_name
          #  writer.copy_file(STYLECSSFILE, file_to_write)

def fin(key):
    
    texte = "Computer scanning ended, details have been saved on " + str(key) + ".\n"
    writer.writer(texte)
    if verif.amovible(key):
        msg0 = "\nDo you want to dismount your device and quit ? (y = yes, n = no)\n"
        writer.writer(msg0)
        if verif.reponse() == 'y':
            verif.dismount(key)
    verif.quitter()

def init():
    
    print('\t\t\t---------- AUDWin ---------')
    print('\t***************************************************************')
    print('\t*\t\t    Computer scanning                         *')
    print('\t*\t\t          Disclaimer !                        *')
    print('\t*\t This sofware only scan your computer                 *')
    print('\t*\t for users, various system information and software.  *')
    print('\t*\t No copy of your data will be performed.              *')
    print('\t***************************************************************')
    print()

    # Begin timer
    begin_scan = time.time()

    key = scanpart()
    unique_dir = str(COMPUTERNAME) + '_' + datetime.now().strftime('%d%m%y%H%M%S')
    log_file_path = str(key) + "/Result_AUDWin/" + datetime.now().strftime('%Y/%m/%d/') + unique_dir + '/' + unique_dir
    log_file, software_dict, services_running_dict = scanpc(log_file_path)
    complement_init(log_file_path, software_dict, services_running_dict)
    writer.writelog(log_file, '\n</div>\n')

    end_scan = time.time()
    total_time_scan = end_scan - begin_scan
    elem = "----------------------- Scan ended ------------------------"
    writer.prepa_log_scan(log_file, elem)
    total_time = 'Computer analyzed in {} seconds.'.format(round(total_time_scan, 2))
    writer.writelog(log_file, total_time)
    writer.writer('Computer analyzed in ' + str(round(total_time_scan, 2)) + ' seconds.\n')

    elementraw = """
        </body>
    </html>"""
    writer.writelog(log_file, elementraw)

    if os.path.isfile(STYLECSSFILE):
        file_name = os.path.basename(STYLECSSFILE)
        file_to_write = str(key) + "/Result_AUDWin/" + datetime.now().strftime('%Y/%m/%d/') + unique_dir + '/'  + file_name
        writer.copy_file(STYLECSSFILE, file_to_write)

    #readandcopy(log_file)
    fin(key)

if __name__ == '__main__':
    init()
