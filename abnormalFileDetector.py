import os
import magic
import hashlib
import sys
import time
import datetime

def check_if_root():
    if not os.getuid() == 0:
        sys.exit('Script must be run as root')
    else:
        print("Good Root")

def defend_against_forkbomb():
    with open('/etc/security/limits.conf', 'a') as limits:
        limits.write('root    hard    nproc  200\ndefender    hard    nproc  50\n')


def get_files():
    folder = '/bin'
    folder2 = '/usr/sbin/'
    filepaths = [os.path.join(folder, f) for f in os.listdir(folder)]
    filepaths += [os.path.join(folder2, f2) for f2 in os.listdir(folder2)]
    files = list(filter(os.path.isfile, filepaths))
    return files


def find_duplicate_files():
    print("+++++++Finding duplicate files+++++++")
    baseline = os.path.getmtime('/home/')
    BLOCK_SIZE = 256
    checked = ''
    for f in files:
        if baseline < os.path.getmtime(f):
            checked += f
            with open(f, 'rb') as fo:
                fb = fo.read(BLOCK_SIZE)
                fileHash = hashlib.md5(fb)
            for f2 in files:
                if f2 not in checked:
                    with open(f2, 'rb') as fo2:
                        fb2 = fo2.read(BLOCK_SIZE)
                        fileHash2 = hashlib.md5(fb2)
                    if fileHash.digest() == fileHash2.digest():
                        if f2 != f:
                            print("DUPLICATE FOUND", f, "last modified: %s" % time.ctime(os.path.getmtime(f)), f2, "last modified: %s" % time.ctime(os.path.getmtime(f2)))
    print()

def find_shell_scripts():
    print("+++++++Finding shell scripts+++++++")
    baseline = os.path.getmtime('/home/')
    for f in files:
        magicBytes = magic.from_file(f)
        if "Bourne-Again shell script" in magicBytes and baseline < os.path.getmtime(f):
            print("SHELL SCRIPT FOUND:", f, "last modified: %s" % time.ctime(os.path.getmtime(f)))
    print()

check_if_root()
defend_against_forkbomb()
files = get_files()
find_shell_scripts()
find_duplicate_files()
