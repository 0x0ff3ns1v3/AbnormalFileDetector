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
    folders = ["/bin", "/usr/sbin", "/usr/bin", "/sbin"]
    filepaths = list()
    files = list()
    for folder in folders:
        filepaths += [os.path.join(folder, f) for f in os.listdir(folder)]
        files += list(filter(os.path.isfile, filepaths))
    return files


def find_duplicate_files():
    print("+++++++Finding duplicate files+++++++")
    baseline = os.path.getmtime('/home/')
    BLOCK_SIZE = 256
    checked = list()
    for f in files:
        checked.append(f)
        if baseline < os.path.getmtime(f):
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
                            checked.append(f2)
                            duplicates.append(f2)
                        if f not in duplicates:
                            duplicates.append(f)
            if len(duplicates) > 0:
                with open('/tmp/duplicates.txt', 'a') as duptxt:
                    for dup in duplicates:
                        duptxt.write(dup + "last modified: " + time.ctime(os.path.getmtime(dup)) + "\n")
                    duptxt.write("\n")
        duplicates = list()    
    print("Done")

def find_shell_scripts():
    print("+++++++Finding shell scripts+++++++")
    baseline = os.path.getmtime('/home/')
    for f in files:
        magicBytes = magic.from_file(f)
        if "Bourne-Again shell script" in magicBytes and baseline < os.path.getmtime(f):
            with open('/tmp/scripts.txt', 'a') as scripttxt:
                scripttxt.write(f + " last modified: " + time.ctime(os.path.getmtime(f)) + "\n")
                scripttxt.write("\n")

    print("Done")

check_if_root()
defend_against_forkbomb()
files = get_files()
find_shell_scripts()
find_duplicate_files()
