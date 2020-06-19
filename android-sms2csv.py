#!/usr/bin/env python3
# android-sms2csv.py

"""android-sms2csv.py extract SMS messages from Android backup files

Usage: python android-sms2csv.py -f android-folder -o sms-messages.csv { -cli | -gui }

Many tools extract SMS messages from Android backups, but I haven't found one
that parses the sms_backup files.
This program extracts SMS from several sources:
  1) com.android.providers.telephony/d_f/[0-9]+_(sms|mms)_backup
  2) com.sec.android.providers.logsprovider/logs.db (aka snippets)
  also Magnet Forensics 'Acquire' uses an agent that collects 'live' SMS:
  3) Magnet Forensics Acquire agent_mmssms.db
  
This program works on Android backups as files in folders.   
Android backups are often packaged as TAR files or AB files (modified TAR format)
which contain the Android filesystem within them. These must be unpacked to
files and folders first for android-sms2csv to work. 
- for TAR files, use 7ZIP or similar (free) program
- for AB files, use Andriller or similar (free) program
TODO: Add auto-scanning or unpacking of TAR and AB files

The following files are detected and reported but don't yet parse:
  4) TODO com.android.providers.telephony/databases/mmssms.db
  5) TODO com.google.android.apps.messaging/databases/bugle_db
      or com.android.messaging/databases/bugle_db
  6) TODO calllog.db
  also look into adding support for whatsapp, facebook, kik etc

In order to obtain an Android backup from a phone in the first place, try the following:
  1) adb.exe -backup -all
  2) andriller
  3) Magnet Forensics Acquire
  *) or any of the many Android backup apps available

Note: this program can be used from the command line or from a GUI window.
It will auto-detect if it's being called from the command line or double-clicked
from a Windows environment, or force it with the options -cli or -gui

Note2: If MMS attachments are found, they will be extracted to the 
'mms-attachments' directory which will be created in the same folder as the output file.

Copyright 2020 Peter Theobald, peter@PeterTheobald.com 
MIT License (see attached LICENSE.txt)
aka: Do what you want with it as long as you include the license notice
"""

# note: the sms_backup files are simple JSON data, compressed with zlib (but without gzip headers)
# find all _backup files, un-zlib, json->csv, dedup, convert date-serial-integers
# fields: address (leading + and digits), body, date (integer), date.sent (integer),
#         status, type, recipients [ list of numbers w or wo leading + ]

# Installation: pip install Gooey

import argparse
import glob
import sys
try:
    from gooey import Gooey, GooeyParser
except ImportError:
    print("Error: Please install Gooey module first. Try 'pip install Gooey'")
    sys.exit(1)
import time
import os
import re
import zlib
import json
import datetime
import csv
import sqlite3

def main_wrapper():
    parser = argparse.ArgumentParser( epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument( '-f', '--folder', help='source folder to find {nnnn}_sms_backup files. Default is current directory.', default='.')
    parser.add_argument( '-o', '--output', help='output csv file. default sms_backup.csv', default='sms_backup.csv')
    group = parser.add_mutually_exclusive_group()
    group.add_argument( '-gui', help='open in gui window', action='store_true', default=False)
    group.add_argument( '-cli', help='use command line options', action='store_true', default=False)
    group.add_argument( '-auto', help='autodetect started in CLI or GUI (default)', action='store_true', default=False)
    args = parser.parse_args()
    if not args.cli and not args.gui:
        args.gui = True
        args.cli = False
        try:
            if sys.stdin.isatty():
                args.gui = False
                args.cli = True
        except AttributeError:
            pass
    if args.cli:
        cli_main( args.folder, args.output)
    else:
        gui_main()

def cli_main( folder: str, output: str):
    execute( folder, output)
    
@Gooey
def gui_main():
    parser = GooeyParser( description = 'android-sms2csv: extract SMS MMS and SMS backups from Android backup image to CSV file')
    parser.add_argument( '-f', '--folder', help='source folder to find {nnnn}_sms_backup files. Default is current directory.', default='.', widget='DirChooser')
    parser.add_argument( '-o', '--output', help='output csv file. default sms_backup.csv', default='sms_backup.csv', widget='FileSaver')
    args = parser.parse_args()
    execute( args.folder, args.output)

def execute( folder: str, output: str):
    # TODO: check if we need to dedup the csv
    notable_locations = [ 'com.android.providers.telephony', 'com.sec.android.providers.logsprovider',
                'com.google.android.apps.messaging', 'com.android.messaging', 'com.android.mms']
    databases = {
        'mmssmsdb': { 'found': False, 'pattern': '^mmssms.db$', 'location':  'com.android.providers.telephony',
                    'desc': 'mmssms.db main sms database', 'function': process_mmssmsdb},
        'smsbackup': { 'found': False, 'pattern': '^\d+_(sms|mms)_backup$', 'location':  'com.android.providers.telephony',
                    'desc': 'sms_backups', 'function': process_smsbackup},
        'logsdb': { 'found': False, 'pattern': '^logs.db$', 'location':  'com.sec.android.provider.logsprovider',
                    'desc': 'logs.db sms snippets', 'function': process_logsdb},
        'magnet_agent_mmssms': { 'found': False, 'pattern': '^agent_mmssms.db$', 'location':  'agent',
                    'desc': 'Magnet Forensics agent live agent_mmssms.db database', 'function': process_magnet_mmssmsdb},
        'bugle': { 'found': False, 'pattern': '^bugle_db$', 'location':  'com.google.android.apps.messaging',
                    'desc': 'New generation bugle_db sms database', 'function': process_bugledb},
        'calllog': { 'found': False, 'pattern': '^calllog.db$', 'location':  'any',
                    'desc': 'calllog', 'function': process_calllog},
        'ab': { 'found': False, 'pattern': '.*\.[aA][bB]$', 'location':  'any',
                    'desc': 'Android AB backup', 'function': process_ab},
        'tar': { 'found': False, 'pattern': '.*\.[tT][aA][rR]$', 'location':  'any',
                    'desc': 'Android backup in TAR archive', 'function': process_tar}
        }
    print('Scanning', folder)
    print('Saving to', output, 'in',os.path.dirname(output))
    with open( output, 'w', newline='', encoding='utf-8') as output_fp:
        csv_writer=csv.writer( output_fp, dialect='excel')
        csv_writer.writerow( ['Address','Name','Date','Date_sent','Recipients','Body','msgtype','Location','Source'])
        for dirpath, dirnames, filenames in os.walk( folder):
            for file in filenames:
                if file in notable_locations:
                    print( 'Found ', os.path.join(dirpath, file))
                for database in databases:
                    if re.match( databases[database]['pattern'], file):
                        databases[database]['found'] = True
                        if databases[database]['location'] != 'any' and databases[database]['location'] not in dirpath:
                            print('Found',os.path.join(dirpath,file),'expected in',databases[database]['location'])
                        else:
                            print('Found',os.path.join(dirpath,file))
                        databases[database]['function']( dirpath, file, os.path.dirname( output), csv_writer)
    print()
    print('Found:')
    for database in databases:
        if databases[database]['found']:
            print( '   ',databases[database]['desc'])
    print('Not Found:')
    for database in databases:
        if not databases[database]['found']:
            print( '   ',databases[database]['desc'])

def process_ab( dir, file, output_dir, csv_writer):
    print('    Please extract with Andriller or similar tool')

def process_tar( dir, file, output_dir, csv_writer):
    print('    Please extract with 7Zip or similar tool')

def process_mmssmsdb( dir, file, output_dir, csv_writer):
    print('    Parser not implemented yet!!')

def process_bugledb( dir, file, output_dir, csv_writer):
    print('    Parser not implemented yet!!')

def process_calllog( dir, file, output_dir, csv_writer):
    print('    Parser not implemented yet!!')


def process_smsbackup( dir, smsbackup_file, output_dir, csv_writer):
    file_fp = open( os.path.join( dir, smsbackup_file), 'rb')
    sms_json = json.loads( zlib.decompress( file_fp.read()))
    file_fp.close()
    count = 0
    # sms_json should be a list of dict's each w fields like address, body, date, date_sent, mms_body etc.
    # sms_json[n] = { 'address': '12125551212', 'body': 'hello world', ...}
    # sms_json[n][recipients] is a list of addresses (phone numbers)
    # sms_json[n][mms_addresses is a list of dict's w fields type, address, charset
    for item in sms_json:
        # item['raw_address'] = item.get('address', '')
        item['address'] = format_address( item.get('address', ''))
        item['name'] = ''
        # item['raw_date'] = item.get('date', '')
        item['date'] = format_date( item.get('date', ''))
        # item['raw_date_sent'] = item.get('date_sent', '')
        item['date_sent'] = format_date( item.get( 'date_sent', ''))
        item['body'] = item.get('body', '')
        item['msgtype'] = format_msgtype( item.get('type', 0))
        item['mms_body'] = item.get('mms_body', '')
        if item['body'] and item['mms_body']:
            item['body'] += '; ' + item['mms_body']
        else:
            item['body'] += item['mms_body']
        item['all_recipients'] = ''
        for recipient in item.get('recipients', []):
            if item['all_recipients']:
                item['all_recipients'] += ', ' + format_address( recipient)
            else:
                item['all_recipients'] = format_address( recipient)
        for recipient_dict in item.get('mms_addresses', {}):
            recipient = recipient_dict.get('address','')
            if item['all_recipients']:
                item['all_recipients'] += ', ' + format_address( recipient)
            else:
                item['all_recipients'] = format_address( recipient)
        # ['Address','Name','Date','Date_sent','Recipients','Body','msgtype','Location','Source']
        csv_writer.writerow( [ item['address'], item['name'], item['date'], item['date_sent'], item['all_recipients'], item['body'], item['msgtype'], '', smsbackup_file])
        count += 1
    print( count, 'messages in', smsbackup_file)

def process_logsdb( dir, database_file, output_dir, csv_writer):
    db = sqlite3.connect( os.path.join( dir, database_file))
    curs = db.cursor()
    count = 0
    # ['Address','Name','Date','Date_sent','Recipients','Body','msgtype','Location','Source']
    for row in curs.execute( 'select number, name, date, type, geocoded_location, m_content from logs'):
        csv_writer.writerow( [ format_address(row[0]), row[1], format_date(row[2]), '', format_address(row[0]), row[5], format_msgtype(row[3]), row[4], database_file ])
        count += 1
    print( count, 'messages in', database_file)
        
def process_magnet_mmssmsdb( dir, database_file, output_dir, csv_writer):
    db = sqlite3.connect( os.path.join( dir, database_file))
    curs = db.cursor()
    # ['Address','Name','Date','Date_sent','Recipients','Body','msgtype','Location','Source']
    mms = {}
    count = 0
    if (not os.path.exists( os.path.join( output_dir, 'mms-attachments'))):
        os.makedirs( os.path.join( output_dir, 'mms-attachments'))
    for row in curs.execute( 'select _id, attachment_type, attachment_data from data'):
        mms[row[0]] = True
        # write out attachment-thread_id-attachment_id.(attachment_type after the /)
        extension = row[1]
        if extension == 'image/*':
            extension = 'jpg'
        if extension == 'video/*':
            extension = 'mp4'
        if '/' in extension:
            extension = extension[extension.find('/')+1:]
        extension = "".join(c for c in extension if c.isalnum()).rstrip() # make safe for filename
        with open( os.path.join( output_dir, 'mms-attachments', 'attachment-'+str(row[0])+'.'+extension), 'wb') as file:
            file.write(row[2])
    for row in curs.execute( 'select _id, body, address, type, date, date_sent from mmssms'):
        body = row[1]
        if row[0] in mms:
            body += ' (attachment ' + str(row[0]) + ')' 
        csv_writer.writerow( [ format_address(row[2]), '', format_date(row[4]), format_date(row[5]), format_address(row[2]), body, format_msgtype(row[3]), '', database_file ])
        count += 1
    print( count, 'messages in', database_file) 
    
def format_msgtype( msgtype) -> str:
    return ['0','1 inbox','2 sent','3','4','5'][int(msgtype)]

def format_address( address: str) -> str:
    # address is either a string or a comma separated list of strings
    return re.sub( ',[+1]*', ',', re.sub( '^[+1]*', '', re.sub( '[- .]', '', address)))

def format_date( date: str) -> str:
    if date in [ '', '0']:
        return ''
    return datetime.datetime.fromtimestamp(int(date)/1000).ctime() + ' UTC'

if __name__ == '__main__':
    main_wrapper()



#str_object1 = open('compressed_file', 'rb').read()
#str_object2 = zlib.decompress(str_object1)
#f = open('my_recovered_log_file', 'wb')
#f.write(str_object2)
#f.close()

#zlib.decompress(data)
#pandas.read_json()
#df.to_csv()

#data=json.load(fp)
#csv_file=csv.writer(f)
#for itemlist in data:
#  csv_file.writerow( itemlist)
