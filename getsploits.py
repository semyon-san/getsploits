#!/usr/bin/python

# Name:    getsploits
# Version: 1.0
# Author:  s3my0n

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import urllib.request
import argparse
import zipfile
import sqlite3
import csv
import sys
import re
import os

EXPLOITS_ARCHIVE_URL = "https://github.com/offensive-security/exploit-database/archive/master.zip"
EXPLOITS_ARCHIVE_FILENAME = "exploits-archive.zip"
EXPLOITS_ARCHIVE_DIR = "exploit-database-master"
EXPLOITS_CSV = "files.csv"
EXPLOITS_CSV_PATH = EXPLOITS_ARCHIVE_DIR + os.sep + EXPLOITS_CSV
EXPLOITS_DB = "exploits.db"

class ParamNames:
    TITLE    = "description"
    TEXT     = "text"
    AUTHOR   = "e_author"
    PLATFORM = "platform"
    TYPE     = "type"
    PORT     = "port"

class Params:
    TITLE, TEXT, AUTHOR, PLATFORM, TYPE, PORT = range(6)

class Param:
    _VALUES = {}
    _name = ""

    def getCode(self, key):
        if not key: return ""
        try:
            if isinstance(key, list):
                return [type(self)._VALUES[i] for i in key]
            else:
                return type(self)._VALUES[key]
        except KeyError:
            raise ValueError('"{0}" is not a supported {1}'.format(key, type(self)._name))

class Platforms(Param):
    _name = "platform"
    PLATFORMS = _VALUES = {
        "aix"            : "1",
        "android"        : "57",
        "arm"            : "46",
        "asp"            : "2",
        "atheos"         : "54",
        "beos"           : "51",
        "bsd"            : "3",
        "bsdi_x86"       : "6",
        "bsd_ppc"        : "4",
        "bsd_x86"        : "5",
        "cfm"            : "47",
        "cgi"            : "7",
        "freebsd"        : "8",
        "freebsd_x86"    : "9",
        "freebsd_x86-64" : "10",
        "generator"      : "11",
        "hardware"       : "12",
        "hp-ux"          : "13",
        "immunix"        : "52",
        "ios"            : "56",
        "irix"           : "14",
        "java"           : "50",
        "jsp"            : "15",
        "linux"          : "16",
        "linux_mips"     : "18",
        "linux_ppc"      : "19",
        "linux_sparc"    : "20",
        "lin_amd64"      : "17",
        "lin_x86"        : "21",
        "lin_x86-64"     : "22",
        "minix"          : "23",
        "mips"           : "55",
        "multiple"       : "24",
        "netbsd_x86"     : "25",
        "netware"        : "48",
        "novell"         : "26",
        "openbsd"        : "27",
        "openbsd_x86"    : "28",
        "osx"            : "30",
        "osx_ppc"        : "29",
        "palm_os"        : "53",
        "perl"           : "59",
        "php"            : "31",
        "plan9"          : "32",
        "qnx"            : "33",
        "sco"            : "34",
        "sco_x86"        : "35",
        "sh4"            : "49",
        "solaris"        : "36",
        "solaris_sparc"  : "37",
        "solaris_x86"    : "38",
        "tru64"          : "39",
        "ultrix"         : "40",
        "unix"           : "41",
        "unixware"       : "42",
        "win32"          : "43",
        "win64"          : "44",
        "windows"        : "45",
        "xml"            : "58"
    }

class Types(Param):
    _name = "type"
    TYPES = _VALUES = {
        "dos"       : "1",
        "local"     : "2",
        "papers"    : "5",
        "remote"    : "3",
        "shellcode" : "4",
        "webapps"   : "6"
    }

class SQLExploitsDB(object):
    """ Creates and queries sql databases """

    TABLE_EXPLOIT = "Exploit"

    COL_ID = "id"
    COL_FILE = "file"
    COL_DESCRIPTION = "description"
    COL_DATE = "date"
    COL_AUTHOR = "author"
    COL_PLATFORM = "platform"
    COL_TYPE = "type"
    COL_PORT = "port"

    def __init__(self, source_csv):
        self._conn = None
        self._db_file = None
        self._csv_file = source_csv

    def gen_db(self, db_file):
        if file_exists(db_file):
            return

        self._db_file = db_file

        self._connect()
        self._create_table()
        self._insert_data_from_csv()
        self._disconnect()

    def _connect(self):
        self._conn = sqlite3.connect(self._db_file)

    def _commit(self):
        self._conn.commit()

    def _disconnect(self):
        self._conn.close()

    def _create_table(self):
        c = self._conn.cursor()
        c.execute("""CREATE TABLE {} (
            {} INTEGER PRIMARY KEY,
            {} TEXT,
            {} TEXT,
            {} TEXT,
            {} TEXT,
            {} TEXT,
            {} TEXT,
            {} INTEGER
        )
        """.format(self.TABLE_EXPLOIT, self.COL_ID, self.COL_FILE, self.COL_DESCRIPTION, self.COL_DATE, self.COL_AUTHOR, self.COL_PLATFORM, self.COL_TYPE, self.COL_PORT))
        
        self._commit()
    
    def _insert_data_from_csv(self):
        print("INSERTING")
        c = self._conn.cursor()

        csv_file = open(self._csv_file)
        
        csv_file.readline() # skip column names
        reader = csv.reader(csv_file)
        for values in reader:
            c.execute("INSERT INTO {} VALUES (?, ?, ?, ?, ?, ?, ?, ?)".format(self.TABLE_EXPLOIT), values)

        csv_file.close()

        self._commit()

### Argument parsing ###

def parse_args(argv):
    usage = "getsploits <title> [options]"

    args = {}

    parser = argparse.ArgumentParser()

    parser.add_argument("-a", dest="archive", action="store_true", help="Download latest exploit archive")
    parser.add_argument("-s", dest="sqlite", action="store_true", help="Generate sqlite database")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-t", dest="threads", type=int, help="Number of threads", default=10)

    search = parser.add_argument_group("Search options")

    search.add_argument(ParamNames.TITLE, help="Text inside title", nargs="?", default="")
    search.add_argument("--text", dest=ParamNames.TEXT, help="Free text search", default="")
    search.add_argument("--type", dest=ParamNames.TYPE, help="Type", nargs="*",
        choices=Types.TYPES.keys(), default="")

    search.add_argument("--platform", dest=ParamNames.PLATFORM, help="Platform", nargs="*",
        choices=Platforms.PLATFORMS.keys(), default="")
    search.add_argument("--author", dest=ParamNames.AUTHOR, help="Author", nargs="*", default="")
    search.add_argument("--port", dest=ParamNames.PORT, help="Port number", nargs="*", default="")

    args = vars(parser.parse_args(argv))

    return args

def print_error(error):
    print("[-] {}".format(error), file=sys.stderr)

def make_params(args):
    params = {}
    params = {
        Params.TITLE    : args[ParamNames.TITLE],
        Params.TEXT     : args[ParamNames.TEXT],
        Params.AUTHOR   : args[ParamNames.AUTHOR],
        Params.PLATFORM : Platforms().getCode(args[ParamNames.PLATFORM]),
        Params.TYPE     : Types().getCode(args[ParamNames.TYPE]),
        Params.PORT     : args[ParamNames.PORT],
    }
    return params

################


### functions ###

def file_exists(path):
    return os.path.isfile(path)

def delete_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass

def ask_yes_no(message, default="N"):
    while True:
        print(message, end="")
        if default == "N":
            print(" (y/N): ", end="")
        else:
            print(" (Y/n): ", end="")

        user_input = input().strip()
        # if user pressed Enter
        if len(user_input) == 0:
            return True if default == "Y" else False
        # if user entered something
        answer = user_input[0].upper()
        if answer == "Y":
            return True
        elif answer == "N":
            return False

def print_progress(subtotal, total):
    print("{:3.0f}%".format(subtotal/total*100), end="\r")

def copyfileobj_progress(fsrc, fdst, progress_callback=None):
    copied = 0
    length = fsrc.length
    chunk_size = 1024*512

    while True:
        buf = fsrc.read(chunk_size)
        if not buf:
            break
        fdst.write(buf)
        copied += len(buf)
        if progress_callback:
            progress_callback(copied, length)

def download(src, dst):
    with urllib.request.urlopen(src) as in_stream, open(dst, "wb") as archive:
        copyfileobj_progress(in_stream, archive, print_progress)

def download_archive():
    to_download = True
    if file_exists(EXPLOITS_ARCHIVE_FILENAME):
        to_download = ask_yes_no("[?] Exploit archive '{}' exists, would you like to download it again?".format(EXPLOITS_ARCHIVE_FILENAME))

    if to_download:
        print("[*] Downloading exploits archive...")
        download(EXPLOITS_ARCHIVE_URL, EXPLOITS_ARCHIVE_FILENAME)

def extract_archive():
    print("[*] Extracting exploits archive...")
    with zipfile.ZipFile(EXPLOITS_ARCHIVE_FILENAME, "r") as z:
        z.extractall()


#################

def main():
    # 1. Parse options

    args = parse_args(sys.argv[1:])

    # 2. Check if option to download new archive

    arg_archive = args["archive"]
    arg_sqlite = args["sqlite"]


    sql_db = SQLExploitsDB(EXPLOITS_CSV_PATH)

    if arg_archive:
        download_archive()
        extract_archive()
        sql_db.gen_db(EXPLOITS_DB)
    elif arg_sqlite or not file_exists(EXPLOITS_DB):
        if not file_exists(EXPLOITS_CSV_PATH):
            download_archive()
            extract_archive()
        delete_file(EXPLOITS_DB)
        sql_db.gen_db(EXPLOITS_DB)

    # 3. Check if search query exists

    params = make_params(args)
    if not any(params.values()):
        print_error("Nothing to search");
        sys.exit(1)

    # 4. Search

    pass

if __name__ == "__main__":
    main()
