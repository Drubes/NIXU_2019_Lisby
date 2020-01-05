#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import sys

color = 1


'''--------------------------------------------------------------------------'''
# the opcodes are in order, index 0 == 0x00.. etc etc etc
# i know it might have been beter to put in a dictionary. but im lazy.
op=['HALT', 'ADD', 'SUB', 'MUL', 'DIV', 'XOR', 'MOD', 'AND', 'OR', 'INV',
'PUSHI', 'PUSHF', 'PUSHSTR', 'PUSHSY', 'PUSHSYRAW', 'PUSHTRUE', 'PUSHFALSE',
'PUSHUNIT', 'PUSHCLOSURE', 'PUSHCONT', 'QUOTED', 'POP', 'CALL', 'TAILCALL',
'RET', 'JT', 'JF', 'JMP', 'STORE', 'STORETOP', 'EQ', 'NEQ', 'GT', 'GE', 'LT',
'LE', 'NOT', 'DECLARE', 'PRINT', 'LIST', 'HEAD', 'TAIL', 'LISTCAT', 'EVAL',
'DUMP', 'NEWENV', 'DEPARTENV']
'''--------------------------------------------------------------------------'''
#opt codes that are followed by a value
has_val = [10, 11,12,13,14,28,29,18,25,26,27,37,39,14,20,19]
has_str = [12]     # opcodes were the value points to the string table
has_sym = [13,14,37]  # opcodes were the value points to the symbol table.

cs = [] # call stack
vs = [] # value stack

failmsg = 'OPCODE NOT REQONIZED'
def do_something (opcode, p):
    #debug(p)
    if opcode == 0:  #HALT
        print R+'[program end]'+RS
        quit()

    if opcode == 1:  #ADD
        vs.append(vs.pop(-1)+vs.pop(-1))
    if opcode == 2:  #SUB
        vs.append(vs.pop(-1)-vs.pop(-1))
    if opcode == 3: #'MUL',
        vs.append(vs.pop(-1)*vs.pop(-1))
    if opcode == 4:#'DIV',


        vs.append(vs.pop(-1)/vs.pop(-1))
    if opcode == 5: #'XOR',
        vs.append(vs.pop(-1)^vs.pop(-1))
    if opcode == 6: #'MOD',
        vs.append(vs.pop(-1)%vs.pop(-1))
    if opcode == 7: #'AND',
        vs.append(vs.pop(-1)&vs.pop(-1))
    if opcode == 8: #'OR',
        vs.append(vs.pop(-1)|vs.pop(-1))
    if opcode == 9: #'INV',
        vs.append(~vs.pop(-1))

    if opcode == 10: #'PUSHI',
        vs.append(u64(file[p+1:p+9]))
        #print failmsg
    if opcode == 11: #'PUSHF',
        print failmsg+" : "+str(opcode)
    if opcode == 12: #'PUSHSTR',
        vs.append(str_ent[u64(file[p+1:p+9])])
    if opcode == 13: #'PUSHSY',
        print failmsg+" : "+str(opcode)
    if opcode == 14: #'PUSHSYRAW',
        print failmsg+" : "+str(opcode)
    if opcode == 15: #'PUSHTRUE',
        print failmsg+" : "+str(opcode)
    if opcode == 16: #'PUSHFALSE',
        print failmsg+" : "+str(opcode)
    if opcode == 17: #'PUSHUNIT',
        vs.append('')
    if opcode == 18: #'PUSHCLOSURE',
        print failmsg+" : "+str(opcode)
    if opcode == 19: #'PUSHCONT',
        print failmsg+" : "+str(opcode)
    if opcode == 20: #'QUOTED',
        print failmsg+" : "+str(opcode)
    if opcode == 21: #'POP',
        print failmsg+" : "+str(opcode)
    if opcode == 22: #'CALL',
        print failmsg+" : "+str(opcode)
    if opcode == 23: #'TAILCALL',
        print failmsg+" : "+str(opcode)
    if opcode == 24: #'RET',
        print failmsg+" : "+str(opcode)
    if opcode == 25: #'JT',
        print failmsg+" : "+str(opcode)
    if opcode == 26: #'JF',
        print failmsg+" : "+str(opcode)
    if opcode == 27: #'JMP',
        print failmsg+" : "+str(opcode)
    if opcode == 28: #'STORE',
        print failmsg+" : "+str(opcode)
    if opcode == 29: #'STORETOP',
        print failmsg+" : "+str(opcode)
    if opcode == 30: #'EQ',
        print failmsg+" : "+str(opcode)
    if opcode == 31: #'NEQ',
        print failmsg+" : "+str(opcode)
    if opcode == 32: # 'GT',
        print failmsg+" : "+str(opcode)
    if opcode == 33: #'GE',
        print failmsg+" : "+str(opcode)
    if opcode == 34: #'LT',
        print failmsg+" : "+str(opcode)
    if opcode == 35: #'LE',
        print failmsg+" : "+str(opcode)
    if opcode == 36: #'NOT',
        print failmsg+" : "+str(opcode)
    if opcode == 37: #'DECLARE',
        print failmsg+" : "+str(opcode)
    if opcode == 38: #'PRINT',
        value = vs.pop(-1)
        try:
            print chr(value)
        except:
            print value
    if opcode == 39: #'LIST',
        print failmsg+" : "+str(opcode)
    if opcode == 40: #'HEAD',
        print failmsg+" : "+str(opcode)
    if opcode == 41: #'TAIL',
        print failmsg+" : "+str(opcode)
    if opcode == 42: #'LISTCAT',
        print failmsg+" : "+str(opcode)
    if opcode == 43: #'EVAL',
        print failmsg+" : "+str(opcode)
    if opcode == 44: #'DUMP',
        print failmsg+" : "+str(opcode)
    if opcode == 45: #'NEWENV',
        print failmsg+" : "+str(opcode)
    if opcode == 46: #'DEPARTENV'
        print failmsg+" : "+str(opcode)

    if opcode in has_val:
        p += 9
    else:
        p +=1
    return p


'''--------------------------------------------------------------------------'''
Z,R,G,Y,B,M,C,W,RS ='','','','','','','','','' #for when you dont like colors
if color == 1:
    Z  = "\033[1;30m"  #Z-black
    R  = "\033[1;31m"  #red
    G  = "\033[1;32m"  #green
    Y  = "\033[1;33m"  #green
    B  = "\033[1;34m"  #blue
    M  = "\033[1;35m"  #magenta
    C  = "\033[1;36m"  #cyan
    W  = "\033[1;37m"  #white
    RS = "\033[0;0m"   #reset
'''--------------------------------------------------------------------------'''
PB = '░▒▓'+'█'*74 +'▓▒░' #pagebreak.

'''--------------------------------------------------------------------------'''
def fail():
    print 'usage ./lisby_EMULATOR.py file-name'
    quit()
'''--------------------------------------------------------------------------'''

def nice_offset(offset):
    return Z+"{0:#0{1}x}:".format(offset,10)+RS
'''--------------------------------------------------------------------------'''

'''--------------------------------------------------------------------------'''

def debug(pointer):
    print "ponter at offset:"+hex(pointer)+"   next 64-bit: "+enhex(file[pointer:pointer+8])
'''--------------------------------------------------------------------------'''

def par_tbl(pointer):
    entries = []
    table_length = u64(file[pointer:pointer+8])
    pointer +=8
    if table_length > 0 :

        for i in range(0,table_length):
            entry_length = u64(file[pointer:pointer+8])
            pointer += 8
            entry_contents =  file[pointer:pointer+entry_length]
            entries.append(entry_contents)
            pointer += entry_length
    return {'pointer':pointer, 'entries':entries}

'''--------------------------------------------------------------------------'''
def run_tape(p,tape_n):
    len_tape = u64(file[p:p+8])
    p += 8
    tape_end = p+len_tape
    while p < tape_end:
        oc = ord(file[p:p+1])
        p = do_something(oc,p)
    return(p)

def dis_tape(p,tape_n):
    len_tape = u64(file[p:p+8])
    p += 8
    tape_end = p+len_tape
    print "-"*80
    '''if tape_n == 0:
        print Y+'[MAIN TAPE]'+RS
    else:
        print Y+'['+sym_ent[tape_n]+']'+RS
    '''
    print "tape number    : "+R+str(tape_n)+RS
    print "length of tape : "+str(len_tape)+" bytes"
    print "tape start     : "+nice_offset(p)
    print "tape end       : "+nice_offset(tape_end)
    print "-"*80

    while p < tape_end: # somthing wrong
        #debug(p)
        oc = ord(file[p:p+1])
        #print oc
        bonus_bytes = 0
        bonus_str = ""
        raw_hex = enhex(file[p:p+1])
        if oc in has_val:
            val = u64(file[p+1:p+9])
            bonus_bytes = 8
            bonus_str = ' , '+hex(val).ljust(10)
            raw_hex = enhex(file[p:p+9])
            if oc in has_str:
                bonus_str += G+'; \"'+str_ent[val]+'\"'+RS
            if oc in has_sym:
                bonus_str += Y+'; ['+sym_ent[val]+']'+RS
        print nice_offset(p+1).ljust(12)+raw_hex.rjust(20)+W+op[oc].rjust(15)+bonus_str+RS
        p += 1+bonus_bytes
    return(p)

'''--------------------------------------------------------------------------'''

if len(sys.argv) != 2:
    fail()
filename = sys.argv[1]
try:
    f=open(filename,"r")
except:
    print '\n\nERROR: could not open file \"'+filename+'\"\n'
    fail()

file = f.read()
magicprefix = file[:8]

if magicprefix != 'LISBY001':
    print filename+' is not a LISBY file.'
    fail()

'''--------------------------------------------------------------------------'''
p = 8 # set pointer to 8 to skip magicprefix

print R+PB+RS
print W+" ".join("  LISBY DEVICE : A TIME MACHINE EMULATOR")
print B+PB+RS

str_tbl = par_tbl(p)
p = str_tbl['pointer']
str_ent=str_tbl['entries']
sym_tbl = par_tbl(p)
p = sym_tbl['pointer']
sym_ent=sym_tbl['entries']

n_tapes = u64(file[p:p+8])
p += 8
print W+PB+"\n\n"
print " Amount of Tapes: "+str(n_tapes)+RS

for i in range(0, n_tapes):
    #print i
    p = run_tape(p,i)
    print PB+"\n"
'''--------------------------------------------------------------------------'''
