#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Extract the opcode from the objdump of a binary
'''

import re
import os
import sys
import getopt
import string
from subprocess import check_output
from collections import Counter

__version__ = "$Id: bin2op.py,v 1.2 2015/12/28 13:21:32 dhn Exp $"
__license__ = "BSD"


def getopts():
    try:
        usage_opt = [
                        "file=", "short", "large", "opcode", "intel",
                        "att", "python", "version", "help"
                    ]

        opts, args = getopt.getopt(sys.argv[1:], "f:sloiapvh", usage_opt)

    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)
    objfile = None
    shellcode = None
    code = None
    syntax = "intel"
    formats = None
    for opt, arg in opts:
        if opt in ("-i", "--intel"):
            syntax = "intel"
        elif opt in ("-a", "--att"):
            syntax = "att"
        elif opt in ("-p", "--python"):
            formats = "python"
        elif opt in ("-f", "--file"):
            objfile = arg
            if os.path.exists(objfile):
                shellcode, code, opcodes, operands = parse(objfile, syntax, formats)
            else:
                print("[!] file does not exist")
                sys.exit(1)
        elif opt in ("-s", "--short"):
            if objfile is not None:
                if formats is not None:
                    shellcode = re.sub(
                                "(.{32})", "\tb\"\\1\"\n",
                                shellcode, 0, re.DOTALL)
                    print("shellcode = (")
                    print(shellcode[:-1])
                    print(")")
                else:
                    shellcode = re.sub(
                                "(.{32})", "\\1\n",
                                shellcode, 0, re.DOTALL)
                    print(shellcode[:-1])
        elif opt in ("-l", "--large"):
            if objfile is not None:
                # FIXME: this is really ugly :(
                if formats is not None:
                    print("shellcode = (")
                for line in code:
                    break #print("", line)
                if formats is not None:
                    print(")")
        elif opt in ("-o", "--opcode"):
            if objfile is not None:
                # FIXME: this is really ugly :(
                unique(opcodes,True)
                print("\n")
                print(counts(opcodes))
                if formats is not None:
                    print("opcodes = (")
                for opcode in opcodes:
                    print("", opcode)
                if formats is not None:
                    print(")")    
                if formats is not None:
                    print("operands = (")
                for operand in operands:
                    print("", operand)
                if formats is not None:
                    print(")")    
                
        elif opt in ("-h", "--help"):
            usage()
        elif opt in ("-v", "--version"):
            print("%s - %s" % (__version__, __license__))
        else:
            assert False, "unhandled option"


def usage():
    print("usage: %s [options]" % __file__)
    print("   -f, --file     The assembly code filename")
    print("   -s, --short    Show less version of opcode")
    print("   -l, --large    Show verbose version of opcode")
    print("   -i, --intel    Use the intel assembly syntax")
    print("   -a, --att      Use the AT&T assembly syntax")
    print("   -p, --python   Format output to python syntax")
    print("")
    print("Example: %s -a -f bindshell/build/bindshell.o -l" % __file__)
    print("         %s -f bindshell/build/bindshell.o -s" % __file__)
    print("         %s -p -f bindshell/build/bindshell.o -s" % __file__)

def nextIndex(string: str, text: str, start: int=0):
    while True:
        try:
            start = text.index(string, start)
            yield start
            start += 1
        except ValueError:
            raise StopIteration

def counts(list):
    #return dict((elem, list.count(elem)) for elem in list)
    return Counter(list)
# function to get unique values 
def unique(list1,verbose): 
  
    # intilize a null list 
    unique_list = [] 
      
    # traverse for all elements 
    for x in list1: 
        # check if exists in unique_list or not 
        if x not in unique_list: 
            unique_list.append(x) 
    # print list 
    if verbose:
        for x in unique_list: 
            print(x, end=",") 
    else:
        return unique_list
# thanks zerosum0x0
def parse(obj, syntax, formats):
    objdump = ['objdump', '-d', '-M', syntax, obj]

    lines = check_output(objdump)
    
    lines = lines.split(b'Disassembly of section')[1]
    
    lines = lines.split(b'\n')[3:]

    shellcode = ""
    code = []
    opcodes = []
    operands = []

    for line in lines:
        line = line.strip()

        tabs = line.split(b'\t')
        if (len(tabs) < 2):
            continue
        bytes = tabs[1].strip()

        instruction = "."
        if (len(tabs) == 3):
            instruction = tabs[2].strip().decode("utf-8")
            instruction_split = instruction.replace('    ',' ').replace('   ',' ').replace('  ',' ').split(' ')
            #print(instruction_split)
            opcode = instruction_split[0] if len(instruction_split) > 0 else 'none' 
            opcodes.append(opcode)                
            operand = instruction_split[1] if len(instruction_split) > 1 else 'none' 
            operands.append(operand)
        
        bytes = bytes.split(b' ')
        shellcodeline = ""
        for byte in bytes:
            shellcodeline +=  byte.decode("utf-8") + " "

        shellcode += shellcodeline
        if formats is not None:
            c = '\t%-*s# %s' % (32, '"'+shellcodeline+'"', instruction)
        else:
            c = '%-*s/* %s */' % (32, '"'+shellcodeline+'"', instruction)
        code.append(c)

    return shellcode, code, opcodes, operands


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        usage()
    else:
        getopts()
