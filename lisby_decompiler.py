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
has_val  = [10, 11,12,13,14,28,29,18,25,26,27,37,39,14,20,19] #opt codes that are followed by a value
has_str  = [12]              # opcodes were the value points to the string table
has_sym  = [13,14,28,29,37]  # opcodes were the value points to the symbol table.
has_jmp  = [25,26,27]        # opcodes that jump
has_tape = [18]              # opcodes with tape reference
has_else = [39]              # opcodes i dont want to show charcter representation of.

jmp_des  = []                # offsets were a jump lands.
'''--------------------------------------------------------------------------'''
Z,R,G,Y,B,M,C,W,RS ='','','','','','','','','' #for when you dont like colors
if color == 1:
    Z  = "\033[1;30m"  #black
    R  = "\033[1;31m"  #red
    G  = "\033[1;32m"  #green
    Y  = "\033[1;33m"  #green
    B  = "\033[1;34m"  #blue
    M  = "\033[1;35m"  #magenta
    C  = "\033[1;36m"  #cyan
    W  = "\033[1;37m"  #white
    RS = "\033[0;0m"   #reset
'''--------------------------------------------------------------------------'''
#table drawing related stuff
o_cw = 10 #offset cell width
i_cw = 8  #index cell width
l_cw = 10 #length cell width
c_cw = 48 #content cell width
tt = "┏"+"─"*o_cw+"┯"+"─"*i_cw+"┯"+"─"*l_cw+"┯"+"─"*c_cw+"┓"  #top table
ht = "┣"+"═"*o_cw+"┿"+"═"*i_cw+"┿"+"═"*l_cw+"┿"+"═"*c_cw+"┫"  #header table
mt = "┣"+"─"*o_cw+"┿"+"─"*i_cw+"┿"+"─"*l_cw+"┿"+"─"*c_cw+"┫"  #middle table
bt = "┗"+"─"*o_cw+"┷"+"─"*i_cw+"┷"+"─"*l_cw+"┷"+"─"*c_cw+"┛"  #bottom table

PB = '░▒▓'+'█'*74 +'▓▒░' #pagebreak.

'''--------------------------------------------------------------------------'''
def fail():
    print 'usage ./lisby_decompiler.py file-name'
    quit()
'''--------------------------------------------------------------------------'''

def nice_offset(offset):
    return Z+"{0:#0{1}x}".format(offset,10)+RS
'''--------------------------------------------------------------------------'''

def tablefi(o,i,l,c):
        print "│ "+str(o).ljust(o_cw-1)+'│ '+str(i).ljust(i_cw-1)+'│ '+str(l).ljust(l_cw-1)+'│ '+str(c).ljust(c_cw-1)+"│"
'''--------------------------------------------------------------------------'''

def par_tbl(pointer):
    entries = []
    table_length = u64(file[pointer:pointer+8])
    pointer +=8
    print "-- entries:"+str(table_length)
    if table_length > 0 :
        print tt
        tablefi("offset","index","length","content")
        print ht
        for i in range(0,table_length):
            entry_length = u64(file[pointer:pointer+8])
            pointer += 8
            entry_contents =  file[pointer:pointer+entry_length]
            entry_contents = entry_contents.replace('\x0a', '\\n')
            entry_hex=''.join(x.encode('hex') for x in entry_contents)
            tablefi(hex(pointer),i,entry_length,entry_contents)
            entries.append(entry_contents)
            pointer += entry_length
        print bt
    return {'pointer':pointer, 'entries':entries}

'''--------------------------------------------------------------------------'''

def dis_tape(p,tape_n):
    #get tape length and caclulate end offset.
    len_tape = u64(file[p:p+8])
    p += 8
    tape_end = p+len_tape
    tape_start=p

    #print tape information
    print "-"*80
    print "tape number    : "+R+str(tape_n)+RS
    print "length of tape : "+str(len_tape)+" bytes"
    print "tape start     : "+nice_offset(p)
    print "tape end       : "+nice_offset(tape_end)
    print "-"*80

    #parsh tape opcodes untill end of tape
    while p < tape_end:
        oc = ord(file[p:p+1])
        bonus_bytes = 0  #  if opcode is followed by a value we inrement this with the length of te value
        bonus_str = ""   #  placehoder for extra information.
        raw_hex = enhex(file[p:p+1])

        if oc in has_val:
            val = u64(file[p+1:p+9])            #get the value that follow the opcode
            bonus_bytes = 8                     #will be added to pointer
            bonus_str = ','+hex(val).ljust(10)
            raw_hex = enhex(file[p:p+9])        #change the rawhex data to include the value

            #optcodes that are followed by a string
            if oc in has_str:
                bonus_str += G+'; \"'+str_ent[val]+'\"'+RS

            #optcodes that are followed by a symbol reference
            elif oc in has_sym:
                bonus_str += Y+'; ['+sym_ent[val]+']'+RS

            #optcodes followed by a tape reference
            elif oc in has_tape:
                bonus_str += R+'; Tape:'+str(val)+RS

            #optcodes that make a jump.
            elif oc in has_jmp:
                bonus_str += Z+'; '+nice_offset(tape_start+val)+RS
                jmp_des.append(tape_start+val)

            #optcodes that are followed by a value but, i dont want to show the charcter representation of.
            elif oc in has_else:
                bonus_str += W+'; \''+str(val)+'\''+RS

            #the rest of the optcode that are followed by a value
            else:
                if val > 0x19 and val < 0x7f:  #if printable charcter
                    bonus_str += W+'; '+str(val).ljust(5)+B+'\''+chr(val)+'\''+RS
                else:
                    bonus_str += W+'; '+str(val)+RS

        #add a green arrow if the offset is a jump destinaton
        if p in jmp_des:
            bonus_str = G+'<--'+RS

        #print the accumilated information
        print(nice_offset(p).ljust(12)+hex(p-tape_start).rjust(7)+raw_hex.rjust(20)+W+op[oc].rjust(15)+bonus_str+RS)

        #move the pointer to next optcode.
        p += 1+bonus_bytes
    return(p)

'''--------------------------------------------------------------------------'''

#check if a argument is passed
if len(sys.argv) != 2:
    fail()

#check if we can open the file
filename = sys.argv[1]
try:
    f=open(filename,"r")
except:
    print '\n\nERROR: could not open file \"'+filename+'\"\n'
    fail()

#read the contence of the file and check if it has the LISBY001 signature
file = f.read()
magicprefix = file[:8]
if magicprefix != 'LISBY001':
    print filename+' is not a LISBY file.'
    fail()

'''--------------------------------------------------------------------------'''

#prit a nice header.
print R+PB+RS
print W+" ".join("  LISBY DEVICE : A DISASSEMBLY TOOL")
print B+PB+RS


#parsh the string table.
print W+"\n\n STRING TABLE"+RS
p = 8 # set pointer to 8 to skip magicprefix
str_tbl = par_tbl(p)
p = str_tbl['pointer']
str_ent=str_tbl['entries']

#parsh the symbol table.
print W+PB+RS
print W+"\n\n SYMBOL TABLE "+RS
sym_tbl = par_tbl(p)
p = sym_tbl['pointer']
sym_ent=sym_tbl['entries']

#get the tape count.
n_tapes = u64(file[p:p+8])
p += 8
print W+PB+"\n\n"
print " Amount of Tapes: "+str(n_tapes)+RS

#parsh the tapes.
for i in range(0, n_tapes):
    #print i
    p = dis_tape(p,i)
    print PB+"\n"
'''--------------------------------------------------------------------------'''
