# android-sms2csv
android-sms2csv.py extract SMS messages from Android backup files

Usage: python android-sms2csv.py -f android-folder -o sms-messages.csv { -cli | -gui }

Many tools extract SMS messages from Android backups, but I haven't found one
that parses the sms_backup files.
This program extracts SMS from several sources:
  1) com.android.providers.telephony/d_f/[0-9]+_(sms|mms)_backup
  2) com.sec.android.providers.logsprovider/logs.db (aka snippets)\
  also Magnet Forensics 'Acquire' uses an agent that collects 'live' SMS:
  3) Magnet Forensics Acquire agent_mmssms.db
  
This program works on Android backups as files in folders.\
Android backups are often packaged as TAR files or AB files (modified TAR format)
which contain the Android filesystem within them. These must be unpacked to
files and folders first for android-sms2csv to work. 
- for TAR files, use 7ZIP or similar (free) program
- for AB files, use Andriller or similar (free) program\
TODO: Add auto-scanning or unpacking of TAR and AB files

The following files are detected and reported but don't yet parse:
  - TODO com.android.providers.telephony/databases/mmssms.db
  - TODO com.google.android.apps.messaging/databases/bugle_db\
      or com.android.messaging/databases/bugle_db
  - TODO calllog.db
  also look into adding support for whatsapp, facebook, kik etc

In order to obtain an Android backup from a phone in the first place, try the following:
  1) adb.exe -backup -all
  2) andriller
  3) Magnet Forensics Acquire\
  or any of the many Android backup apps available

Note: this program can be used from the command line or from a GUI window.
It will auto-detect if it's being called from the command line or double-clicked
from a Windows environment, or force it with the options -cli or -gui

Note2: If MMS attachments are found, they will be extracted to the 
'mms-attachments' directory which will be created in the same folder as the output file.

```Copyright 2020 Peter Theobald, peter@PeterTheobald.com
MIT License (see attached LICENSE.txt)
aka: Do what you want with it as long as you include the license notice
```
