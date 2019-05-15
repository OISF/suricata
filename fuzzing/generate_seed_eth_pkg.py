#!/usr/bin/env python2

import os
import stat
import subprocess

def main():
    with open("broken","rb") as f:
        byte = bytearray(f.read())

    # mov eax,04
    byte[128] = b'\xb8'
    byte[129] = b'\x04'
    byte[130] = b'\x00'
    byte[131] = b'\x00'
    byte[132] = b'\x00'

    # mov edx,24
    byte[143] = b'\xba'
    byte[144] = b'\x24'
    byte[145] = b'\x00'
    byte[146] = b'\x00'
    byte[147] = b'\x00'

    # int 80
    byte[148] = b'\xcd'
    byte[149] = b'\x80'

    #print("[+] write file ...")
    open('b.out','wb').write(byte)
    os.chmod('b.out',stat.S_IXUSR | stat.S_IRUSR)

    subprocess.call('./b.out')

    #cleanup
    subprocess.call(['rm','-rf','b.out'])

if __name__ == "__main__":
	main()

