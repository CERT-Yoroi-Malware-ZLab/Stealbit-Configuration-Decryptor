#! /usr/bin/env python 
# -*- coding: utf-8 -*- 
# vim:fenc=utf-8 
# 
# Copyright © 2021 Yoroi Srl.  
# Author: zlab@yoroi.company 
# 
# Distributed under terms of the CreativeCommons CC-BY license. 
  
import re 
import sys
import os
from optparse import OptionParser
from os import path,walk 
from io import open 
  
def decodebuf(buffer): 
    result=bytearray(124) 
    for i in range(124): 
        result[i] = buffer[i + 0x10] ^ buffer[i & 0xf] 
    return result 
  
  
def check_header_and_decode(file): 
    print ("[+] Reading: {}".format(file)) 
    data = open(file, 'rb').read() 
    offset = re.search(b'\xff\x17\x18\x19\x20\x00\x00\x00\x00\x00\x00', data) 
    if offset != None: 
        print("[-] Pattern Offset: {}".format(hex(offset.start()))) 
        real_offset = offset.start()+0xb 
        print("[-] Real Blob offset: {}".format(hex(real_offset)))
        buf = data[real_offset:real_offset+0x8c] 
        res = decodebuf(buf) 
        blob = bytes.fromhex(bytearray.hex(res)).decode("ASCII")
        arr = [x for x in blob.split('\x00') if x != '']
        print("[+] Decoded ID: {} C2: {}".format(arr[0], ' '.join(arr[1:]) ) )
    else: 
        print("[+] No StealBit Magic header found") 
  
if __name__ == '__main__': 
    print("""
   _____ _             _ ____  _ _      _____  __          _____                     _                    ___  __ 
  / ____| |           | |  _ \\(_) |    / ____|/ _|        |  __ \\                   | |                  / _ \\/_ |
 | (___ | |_ ___  __ _| | |_) |_| |_  | |    | |_ __ _    | |  | | ___  ___ ___   __| | ___ _ __  __   _| | | || |
  \\___ \\| __/ _ \\/ _` | |  _ <| | __| | |    |  _/ _` |   | |  | |/ _ \\/ __/ _ \\ / _` |/ _ \\ '__| \\ \\ / / | | || |
  ____) | ||  __/ (_| | | |_) | | |_  | |____| || (_| |_  | |__| |  __/ (_| (_) | (_| |  __/ |     \\ V /| |_| || |
 |_____/ \\__\\___|\\__,_|_|____/|_|\\__|  \\_____|_| \\__, (_) |_____/ \\___|\\___\\___/ \\__,_|\\___|_|      \\_/  \\___(_)_|
                                                  __/ |                                                           
                                                 |___/                                                            
""")
    print()
    print("Author: Yoroi Malware ZLAB")
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="filename", help="file or folder of the lockbit sample/s", metavar="FILE")
    (options, args) = parser.parse_args()
    path = options.filename
    if path is None: 
        print("[!] You should specify a valid file or direcory with -f option")
        sys.exit(1)
    if os.path.isfile(path): 
        check_header_and_decode(path) 
    elif os.path.isdir(path): 
        files = [] 
        for (dirpath, dirnames, filenames) in walk(path): 
            for file in filenames:
                check_header_and_decode(os.path.join(dirpath, file)) 
    else: 
        print("Not File Found")
        sys.exit(1)