#!/usr/bin/python3

from sys import stdout
from time import sleep
import os
from csv import DictWriter
from shutil import copy2

def copy_file(source, destination):
    
    file_name = os.path.basename(source)
    try:
        copy2(source, destination)
        if os.path.isfile(destination):
            msg = "\n" + file_name + " has been copied !\n"
            writer(msg)
        else:
            raise IOError
    except (IOError, PermissionError):
        msg = "\nUnable to copy " + file_name + " ! :\nPermission denied !"
        writer(msg)

def prepa_log_scan(logtowrite, elem):
    
    elem0 = '*' * len(elem)
    writelog(logtowrite, elem0 + '<br>\n' + elem + '<br>\n' + elem0 + '<br>\n<br>\n')

def writer(txt, timeout=100, eol=True):
    
    try:
        timeout = timeout / 400000  
        for char in txt:
            print(char, end='')
            stdout.flush()       
            if not char in ' \n\t': 
                sleep(timeout)
        if eol:
            print()
    except OSError:
        pass

def writelog(log_file, element):
    
    # print('log_file sent to writelog : ', log_file)
    dir2create = os.path.dirname(os.path.abspath(log_file))
    # print (dir2create)
    if not os.path.exists(dir2create):
        os.makedirs(dir2create)
    with open(log_file, mode='a', encoding='utf-8') as logfile:
        logfile.write(element)

def write_csv(log_file, fieldnames, element_dict):

    with open(log_file, mode='w', newline='', encoding='utf-8-sig') as csvfile:
        writercsv = DictWriter(csvfile, delimiter=';', fieldnames=fieldnames)
        writercsv.writeheader()
        # for _, values in sorted(element_dict.items()):
        for _, values in element_dict.items():
            writercsv.writerow(values)

def _row2tr(row, attr):

    cols = row.split(';')
    bal1 = '<' + attr + '>'
    bal2 = '</' + attr + '>'
    tojoin = '<TR>'
    for data in cols:
        tojoin += bal1 + data + bal2
    tojoin += '</TR>'
    return tojoin

def csv2html(csv_file, summary):

    htmltxt = '<TABLE summary="' + summary + '">\n'
    with open(csv_file, mode='r', encoding='utf-8-sig') as csvfile:
        readercsv = csvfile.read()
    for rownum, row in enumerate(readercsv.split('\n')):
        if row != '':
            # Prepare header
            if rownum == 0:
                # print(row)
                htmlrow = _row2tr(row, 'TH')
            else:
                htmlrow = _row2tr(row, 'TD')
            htmlrow = '  <TBODY>%s</TBODY>\n' % htmlrow
            htmltxt += htmlrow
    htmltxt += '</TABLE>\n'
    return htmltxt
