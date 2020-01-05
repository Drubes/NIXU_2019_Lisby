#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import copy
import code
import sys
import os
color = 1

#tape starts tape 6
t1=0x518
t2=0x53d
t3=0x563
t4=0x592
t5=0x652
t6=0x722
breakpoints=[t1,t2,t3,t4,t6]
ttyout=open('/dev/pts/0', 'w') # environments debug output tty
'''-----------------------------------------------------------------------------
sorry for the spagetti,
this thing was suppose to remain small, but i got a bit out of hand.
-----------------------------------------------------------------------------'''
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
has_jmp = [22,24,25,26,27]

output = ""
cs = [] # call stack
rs = [] # return stack
vs = [] # value stack
sl = [] # symbol list (contains dictonaries with values according to environment)
nextparent = 0
ep = 0  # environment pointer.
tp = 0  # tape pointer.
ts = [] # transsexu... errrrrr.. i mean tape start
step = 0
failmsg = 'OPCODE NOT REQONIZED'
lastcm = ""
'''--------------------------------------------------------------------------'''
Z,R,G,Y,B,M,C,W,RS ='','','','','','','','','' #for when you dont like colors
if color == 1:
    Z  = "\033[1;30m"  #Zw..black
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
S= "░▒▓ "
E= " ▓▒░"

def printsym(s):
    tmp_list=[]
    for i in range(0,len(sl)):
        if s in sl[i]:
            tmp_list.append(sl[i].get(s))
            print 'env'+str(i)+" : "+str(sl[i].get(s))
    return tmp_list
def printlist(l):
    str=""
    for c in l:
        str+=chr(c)
    print str

def printstack(s,st):
    if st=="cs":
        print G+"callstack:"+RS
        for i in range(0, len(s)):
            print nice_offset(s[i])
    if st=="vs":
        print B+"valuestack:"+RS
        for i in range(0, len(s)):
            print B+'\"'+str(s[i])+'\"'+RS
def dis(p):
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
    try:
        print nice_offset(p).ljust(12)+hex(p-ts[tp]).rjust(7)+raw_hex.rjust(20)+W+op[oc].rjust(15)+bonus_str+RS
    except:
        print nice_offset(p)
        print hex(p-ts[tp])
        print raw_hex
        print R+hex(oc)
        print bonus_str



def do_something (opcode, p):

    tmp_p = p
    #debug(p)
    #print nice_offset(p)
    global lastcm
    global happy_ending
    global output
    global cs
    global vs
    global ep
    global tp
    global ts
    global step
    global nextparent
    d = 0
    if p in breakpoints:
        print "-"*80
        print R+"BREAKPOINT "+str(breakpoints.index(p))+" @"+hex(p)+RS
        dis(p)
        d=1

    try :
        value = u64(file[p+1:p+9])
    except:
        value = 0
    for i in range(0, len(ts)):
        if p > ts[i]:
            tp =  i

    if opcode == 0:  #HALT
        if p == happy_ending-1:
            print G+'[program end]'+RS
        else:
            print R+'[program ended unexpectly]'+RS
        print output
        quit()
    '''------------OPERANTS-----------'''
    if opcode == 1:  #ADD
        vs.append(vs.pop(-1)+vs.pop(-1))
    if opcode == 2:  #SUB
        first=vs.pop(-1)
        second=vs.pop(-1)
        if isinstance(first, list):
            first = 0
        if isinstance(second, list):
            second = 0
        vs.append(first-second)
        #vs.append(vs.pop(-1)-vs.pop(-1))
    if opcode == 3: #'MUL',
        vs.append(vs.pop(-1)*vs.pop(-1))
    if opcode == 4:#'DIV',
        vs.append(vs.pop(-1)/vs.pop(-1))
    '''-------BITWISE-OPERANTS--------'''
    if opcode == 5: #'XOR',
        first=vs.pop(-1)
        second=vs.pop(-1)
        if isinstance(first, list):
            first = 0
        if isinstance(second, list):
            second = 0
        vs.append(first^second)
    if opcode == 6: #'MOD',
        print hex(p)
        first=vs.pop(-1)
        second=vs.pop(-1)
        if isinstance(first, list):
            first = 0
            print "sumtingk wong"
        if isinstance(second, list):
            second = 0
            print "sumtingk wong"
        vs.append(first%second)
        #print "mod"
        #vs.append(vs.pop(-1)%vs.pop(-1))
    if opcode == 7: #'AND',
        vs.append(vs.pop(-1)&vs.pop(-1))
    if opcode == 8: #'OR',
        vs.append(vs.pop(-1)|vs.pop(-1))
    if opcode == 9: #'INV',
        vs.append(~vs.pop(-1))

    '''-----------PUSSIES------------'''
    if opcode == 10: #'PUSHI',
        vs.append(value)
    if opcode == 11: #'PUSHF',
        vs.append(value)  #i dont care atm if its a float or a int.
    if opcode == 12: #'PUSHSTR',
        vs.append(str_ent[value])
    if opcode == 13: #'PUSHSY',  HEhehhehe .. PUSSY
        if sl[ep][value] != "---(n/a)---":
            temp_var=copy.deepcopy(sl[ep][value])
        else:
            parent = sl[ep][-1]
            found =0
            count =0
            while found == 0:
                if sl[parent][value] != "---(n/a)---":
                    temp_var = copy.deepcopy(sl[parent][value])
                    found = 1
                else:
                    parent = sl[parent][-1]

                count +=1
                #if count > len(sl):
                #    dis(p)
                #    debug(p)


                if count > len(sl): #hack
                    for i in range(0,len(sl)-1):
                        if sl[len(sl)-1-i][value] != "---(n/a)---":
                            temp_var = sl[len(sl)-1-i][value]
                            found =1
                            print i
                            print sl[len(sl)-1-i][value]

                            debug(p)
        if type(temp_var) == list:  #fuck you python
            temp_var =copy.deepcopy(temp_var)
        vs.append(temp_var)

    if opcode == 14: #'PUSHSYRAW',
        print failmsg+" : "+str(opcode)
    if opcode == 15: #'PUSHTRUE',
        vs.append("TRUE")
    if opcode == 16: #'PUSHFALSE',
        vs.append("FALSE")
    if opcode == 17: #'PUSHUNIT',
        vs.append([])
    ''' ---------------------------------------------------'''
    if opcode == 18: #'PUSHCLOSURE', WTF IS THIS SHIT >_<
        vs.append(value)
        #nextparent = ep
    if opcode == 19: #'PUSHCONT',
        print failmsg+" : "+str(opcode)

    if opcode == 20: #'QUOTED', # increases quoting level of next value push
        print failmsg+" : "+str(opcode) # ¯\_(ツ)_/¯

    if opcode == 21: #'POP',
        vs.pop(-1)
        #print "nope"
    if opcode == 22: #'CALL',
        tape_nr = vs.pop(-1)
        sl.append([])
        for i in range(0, len(sym_ent)):
            sl[-1].append("---(n/a)---")
        sl[-1].append(ep)
        ep = len(sl)-1
        tmp_p=p+1
        #tape_nr = vs.pop(-1)
        p=ts[tape_nr]
        rs.append(tmp_p) #to push return pointer or not to push return pointer thats the question.

    if opcode == 23: #'TAILCALL',
        print failmsg+" : "+str(opcode)
    if opcode == 24: #'RET',
        p = rs.pop(-1)-1
        old_ep = ep
        ep = sl[ep][-1]
    '''-----------JMPS--------------'''
    if opcode == 25: #'JT',
        if vs.pop(-1)== "TRUE":
            p = ts[tp]+value
        else:
            p +=8

    if opcode == 26: #'JF',
        tmp = vs.pop(-1)
        if tmp == "FALSE":
            p = ts[tp]+value
        else:
            p +=8
    if opcode == 27: #'JMP',
        p = ts[tp]+u64(file[p+1:p+9])

    '''-----------STORIES-----------'''
    if opcode == 28: #'STORE',
        tmp_var=copy.deepcopy(vs.pop(-1))
        if sl[ep][value] != "---(n/a)---":
            sl[ep][value] = tmp_var
        else:
            parent = sl[ep][:-1]
            found = 0
            count = 0
            while found == 0:
                if sl[ep][value] != "---(n/a)---":
                    sl[parent][value] = tmp_var
                    parent = sl[parent][-1]
                    found = 1
                count +=1
                if count > len(sl): #hack
                    for i in range(0,len(sl)-1):
                        if sl[len(sl)-1-i][value] != "---(n/a)---":
                            sl[len(sl)-1-i][value] = tmp_var
                            found =1
                            print i
                            print sl[len(sl)-1-i][value]

                            debug(p)

    if opcode == 29: #'STORETOP',
        sl[0][value]=vs.pop(-1)

    '''---------COMPARISONS---------'''
    if opcode == 30: #'EQ',
        v1=vs.pop(-1)
        v2=vs.pop(-1)
        if v1 == v2:
            vs.append("TRUE")
        else:
            vs.append("FALSE")
    if opcode == 31: #'NEQ',
        if vs.pop(-1) != vs.pop(-1):
            vs.append("TRUE")
        else:
            vs.append("FALSE")
    if opcode == 32: # 'GT',
        if vs.pop(-1) > vs.pop(-1):
            vs.append("TRUE")
        else:
            vs.append("FALSE")
    if opcode == 33: #'GE',
        if vs.pop(-1) >= vs.pop(-1):
            vs.append("TRUE")
        else:
            vs.append("FALSE")
    if opcode == 34: #'LT',
        if vs.pop(-1) < vs.pop(-1):
            vs.append("TRUE")
        else:
            vs.append("FALSE")
    if opcode == 35: #'LE',
        if vs.pop(-1) <= vs.pop(-1):
            vs.append("TRUE")
        else:
            vs.append("FALSE")
    if opcode == 36: #'NOT',
        if vs.pop(-1) == 1:
            vs.append("TRUE")
        else:
            vs.append("FALSE")

    '''-----------------------------'''
    if opcode == 37: #'DECLARE',
        sl[ep][value]="SEATFILLER"
    if opcode == 38: #'PRINT',
        val = vs.pop(-1)
        if isinstance(val, list):
            tmp =""
            for x in val:
                tmp += chr(x)
            print tmp
            print enhex(tmp)
            output+=tmp
        else:
            try:
                print chr(val)
                output+=chr(val)
            except:
                print val
                output+=str(val)
    if opcode == 39: #'LIST',
        tmp_list = []

        for i in range(0,value):
            tmp=vs.pop(-1)
            if isinstance(tmp, list):
                tmp_list.extend(tmp)
            else:
                tmp_list.append(tmp)
            #print tmp_list
        vs.append(tmp_list)
    if opcode == 40: #'HEAD',      who doesn't love some head.
        try :
            tmplist = copy.deepcopy(vs.pop(-1))
            vs.append(tmplist.pop(0))
        except:
            fail =1

    if opcode == 41: #'TAIL',
        try :
            tmplist = copy.deepcopy(vs.pop(-1))
            tmplist.pop(0)
            vs.append(tmplist)
        except:
            fail = 1

    if opcode == 42: #'LISTCAT',
        tmp_list = vs.pop(-1)
        vs.append(tmp_list+vs.pop(-1))

    if opcode == 43: #'EVAL',
        print failmsg+" : "+str(opcode)

    if opcode == 44: #'DUMP',
        print failmsg+" : "+str(opcode)

    if opcode == 45: #'NEWENV',
        sl.append([])
        for i in range(0, len(sym_ent)):
            sl[-1].append("---(n/a)---")
        sl[-1].append(ep)
        ep = len(sl)-1

    if opcode == 46: #'DEPARTENV'
        ep = sl[ep][-1]
    if opcode > 46:
        print failmsg+" : "+str(opcode)+" badjump???"


    if opcode in has_val and opcode not in has_jmp:
        p += 9
    else:
        p +=1

    if tmp_p in breakpoints:
        debug(tmp_p)
        dis(p)
        print "-"*80
        if step == 1:
            breakpoints.pop()
            step = 0
        cm = raw_input()
        if cm == "\n":
            cm = lastcm
        if cm == "s\n":
            breakpoints.append(p)
            step=1
        if "b " in cm:
            breakpoints.append(cm[1:-1])
        if cm == "c\n":
            cm = ""

        if cm == "p\n":
            code.interact(local=dict(globals(), **locals()))
        lastcm = cm
    return p



'''--------------------------------------------------------------------------'''
def fail():
    print 'usage ./lisby_EMULATOR.py file-name'
    quit()
'''--------------------------------------------------------------------------'''

def nice_offset(offset):
    return Z+"{0:#0{1}x}".format(offset,10)+RS
'''--------------------------------------------------------------------------'''

'''--------------------------------------------------------------------------'''

def debug(p):
    global cs
    global vs
    global ep
    global tp
    global ts
    print Z+"ponter at offset:"+nice_offset(p)+Z+"   next 64-bit: "+enhex(file[p:p+8])+Y+" ep: "+str(ep)+RS
    print B+"value stack:"+RS
    for i in range(0, len(vs)):
        print B+str(vs[i])+RS

    env = Y+"environments:\n"
    sym_str="   |"
    for x in sym_ent:
        sym_str += str(x).ljust(12)+"|"
    env += Y+sym_str+"PARENT".ljust(12)+"|"+"\n"
    env += "-"*len(sym_str)+"\n"
    for i in range(0,len(sl)):
        env_str = Y+str(i).ljust(3)+"|"
        for x in sl[i]:
            if x == "---(n/a)---":
                env_str+="".ljust(12)+'|'
            else:
                env_str+=str(x)[0:12].ljust(12)+'|'
        env +=  env_str+"\n"
    ttyout.write(env)
    print "call stack:"
    for i in range(0, len(rs)):
        print nice_offset(rs[i])


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
def run_tape(p):
    len_tape = u64(file[p:p+8])
    p += 8
    tape_end = p+len_tape
    if file[p:p+1] == "":
        print R+"[ERROR: TAPE IS BROKEN]"+RS
        quit()
    while 1:
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
            val = value
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

#fill string list
str_tbl = par_tbl(p)
p = str_tbl['pointer']
str_ent=str_tbl['entries']

#fill symbol lists
sym_tbl = par_tbl(p)
p = sym_tbl['pointer']
sym_ent=sym_tbl['entries']
sl.append([])
for i in range(0,len(sym_ent)):
    sl[0].append("---(n/a)---")
sl[0].append(0)
#get number of tapes
n_tapes = u64(file[p:p+8])
p += 8

# get tape lengths and offsets.
tmp_p = p
for i in range(0, n_tapes):
    tape_len = u64(file[tmp_p:tmp_p+8])
    tmp_p+8
    if i == 0:
        happy_ending=tmp_p+8+tape_len #to check if the program din't land in a other 0x00 by mistake
    ts.append(tmp_p+7)
    tmp_p += tape_len+8


run_tape(p)

'''--------------------------------------------------------------------------'''
