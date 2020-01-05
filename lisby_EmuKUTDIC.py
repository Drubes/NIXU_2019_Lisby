#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import copy
import code
import sys

color = 1
breakpoints=[0x616]


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
has_jmp = [22,24,25,26,27]

output = ""
cs = [] # call stack
rs = [] # return stack
vs = [] # value stack
sl = [] # symbol list (contains dictonaries with values according to environment)

ep = 0  # environment pointer.
tp = 0  # tape pointer.
ts = [] # transsexu... errrrrr.. i mean tape start

failmsg = 'OPCODE NOT REQONIZED'

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
    #dis(p)
    #print nice_offset(p)
    global happy_ending
    global output
    global cs
    global vs
    global ep
    global tp
    global ts
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
        #print vs[len(vs)-1]
    if opcode == 2:  #SUB
        vs.append(vs.pop(-1)-vs.pop(-1))
    if opcode == 3: #'MUL',
        vs.append(vs.pop(-1)*vs.pop(-1))
    if opcode == 4:#'DIV',
        vs.append(vs.pop(-1)/vs.pop(-1))
    '''-------BITWISE-OPERANTS--------'''
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

    '''-----------PUSSIES------------'''
    if opcode == 10: #'PUSHI',
        vs.append(value)
    if opcode == 11: #'PUSHF',
        #print G+"PUSH FLOAT"+RS
        vs.append(value)  #i dont care atm if its a float or a int.
    if opcode == 12: #'PUSHSTR',
        vs.append(str_ent[value])
    if opcode == 13: #'PUSHSY',  HEhehhehe .. PUSSY
        #print Y+sym_ent[value]+B+" is pushed to stack.\n Value: "+str(sl[value][ep])+RS
                #tmp_var=vs.pop(-1)
        #print sl[ep]
        if sl[ep][value] != "---(n/a)---":
            temp_var=copy.deepcopy(sl[ep][value])
        else:
            parent = sl[ep][-1]
            found =0
            #print M+"current environment : "+str(ep)
            while found == 0:
                #print parent
                #print value
                if sl[parent][value] != "---(n/a)---":
                    temp_var = copy.deepcopy(sl[parent][value])
                    found = 1
                    #print sym_ent[value]+" found in env :"+str(parent)
                else:
                    #print sym_ent[value]+" not found in env :"+str(parent)
                    parent = sl[parent][-1]
        #if temp_var != "":
        #    vs.append(temp_var)
        if type(temp_var) == list:  #fuck you python
            #print "IS A FUCKING LIST"
            temp_var =copy.deepcopy(temp_var)
        vs.append(temp_var)
        #print B+str(temp_var)+" is pushed to stack"
        ##printstack(vs,"vs")

    if opcode == 14: #'PUSHSYRAW',
        print failmsg+" : "+str(opcode)
    if opcode == 15: #'PUSHTRUE',
        vs.append("TRUE")
    if opcode == 16: #'PUSHFALSE',
        vs.append("FALSE")
    if opcode == 17: #'PUSHUNIT',
        vs.append([])
        ##print R+"nope"
    ''' ---------------------------------------------------'''
    if opcode == 18: #'PUSHCLOSURE', WTF IS THIS SHIT >_<
        #debug(p)
        #cs.append(ts[value])
        #cs.append(value)
        vs.append(value)
        #sl.append({"pp":ep})
        #ep = len(sl)-1
        ##print Y+str(ep)+RS
        ##print sl
        ##print M+"new environment: "+str(ep)+" parent :"+str(sl[ep].get("pp"))
    if opcode == 19: #'PUSHCONT',
        print failmsg+" : "+str(opcode)

    if opcode == 20: #'QUOTED', # increases quoting level of next value push
        print failmsg+" : "+str(opcode) # ¯\_(ツ)_/¯

    if opcode == 21: #'POP',
        vs.pop(-1)
        ##print failmsg+" : "+str(opcode)
    if opcode == 22: #'CALL',
        #debug(p)
        #sl.append({"pp":ep})
        #ep = len(sl)-1

        #sl.append({"pp":ep})
        sl.append([])
        for i in range(0, len(sym_ent)):
            sl[-1].append("---(n/a)---")
        sl[-1].append(ep)


        ep = len(sl)-1
        ##print Y+str(ep)+RS
        ##print sl
        #print M+"new environment: "+str(ep)+" parent :"+str(sl[ep][-1])
        tmp_p=p+1
        tape_nr = vs.pop(-1)
        p=ts[tape_nr]
        #print G+"call is made to :"+R+"TAPE "+str(tape_nr)+RS+" @ "+nice_offset(p)
        #print "push returnpointer : "+nice_offset(tmp_p)
        rs.append(tmp_p) #to push return pointer or not to push return pointer thats the question.
        ##print failmsg+" : "+str(opcode)

    if opcode == 23: #'TAILCALL',
        print failmsg+" : "+str(opcode)
    if opcode == 24: #'RET',
        p = rs.pop(-1)-1
        old_ep = ep
        ep = sl[ep][-1]
        #ep = ep-1
        #print Y+str(ep)
        #print G+"return to:"+nice_offset(p)
        #debug(p)
        #printstack(cs,"cs")
    '''-----------JMPS--------------'''
    if opcode == 25: #'JT',
        if vs.pop(-1)== "TRUE":
            p = ts[tp]+value
            #print G+"jump taken"+RS
        ##print failmsg+" : "+str(opcode)
        else:
            p +=8
        #print nice_offset(p)

    if opcode == 26: #'JF',
        tmp = vs.pop(-1)
        #print tmp
        if tmp == "FALSE":
            p = ts[tp]+value
            #print G+"jump taken"+RS
        else:
            p +=8

        ##print failmsg+" : "+str(opcode)
    if opcode == 27: #'JMP',
        p = ts[tp]+u64(file[p+1:p+9])

    '''-----------STORIES-----------'''
    if opcode == 28: #'STORE',
        tmp_var=copy.deepcopy(vs.pop(-1))
        if sl[ep][value] != "---(n/a)---":
        #if sym_ent[value] in sl[ep]:
            #sl[ep].update({sym_ent[value]:tmp_var})
            sl[ep][value] = tmp_var
        else:
            parent = sl[ep][:-1]
            found = 0
            #print M+"current environment : "+str(ep)
            while found == 0:
                #if sym_ent[value] in sl[parent]:
                if sl[ep][value] != "---(n/a)---":
                    #sl[parent].update({sym_ent[value]:tmp_var})
                    #parent = sl[parent]["pp"]
                    sl[parent][value] = tmp_var
                    parent = sl[parent][-1]
                    #print sym_ent[value]+" found in env :"+str(parent)
                    found = 1
        #debug(p)

    if opcode == 29: #'STORETOP',
        sl[0][value]=vs.pop(-1)
        #if sym_ent[value] in sl[0]:
            #sl[0].update({sym_ent[value]:vs.pop(-1)})
        #try:

        #    #print sl[0]
        #else:

        #    debug(p)

    '''---------COMPARISONS---------'''
    if opcode == 30: #'EQ',
        v1=vs.pop(-1)
        v2=vs.pop(-1)
        if v1 == v2:
            #print G+str(v1)+":"+str(v2)+" is equal TRUE pushed"
            vs.append("TRUE")
        else:
            #print G+str(v1)+":"+str(v2)+" is not equal FALSE pushed"
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
        #print failmsg+" : "+str(opcode)
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
        #print ep
        #print value
        #print sl
        sl[ep][value]="SEATFILLER"
        #sl[value][ep]
    if opcode == 38: #'PRINT',
        val = vs.pop(-1)
        #print PB
        if isinstance(val, list):
            tmp =""
            for x in val:
                tmp += chr(x)
            print tmp
            output+=tmp
        else:
            try:
                print chr(val)
                output+=chr(val)
            except:
                print val
                output+=str(val)
        #print PB
    if opcode == 39: #'LIST',
        #if value != 0:
        tmp_list = []

        for i in range(0,value):
        #    tmp_list.append(vs.pop(-1))
            tmp=vs.pop(-1)
            if isinstance(tmp, list):
                tmp_list+tmp
            else:
                tmp_list.append(tmp)
            #print i
        #print tmp_list
        vs.append(tmp_list)
        #else:
        #    #print R+"nop"+RS

    if opcode == 40: #'HEAD',      who doesn't love some head.
        #temp_list = vs.pop(-1)
        #temp_list.pop(-1)
        #vs.append(temp_list)
        ##print failmsg+" : "+str(opcode)
        try :
            tmplist = copy.deepcopy(vs.pop(-1))

            vs.append(tmplist.pop(0))
            #print B+"\""+str(tmplist)+"\""+M+" is pushed to stack"+RS
        except:
            fail =1
            ##print tmp_list
            #print R+"[ERROR : EMPTY LIST] @ "+nice_offset(p)+G+str(vs).rjust(5)+RS
            #vs.append("FALSE")# PUSH A ERROR ??
            #debug(p)
            #quit()

    if opcode == 41: #'TAIL',
        try :
            tmplist = copy.deepcopy(vs.pop(-1))
            #print tmplist
            tmplist.pop(0)
            vs.append(tmplist)
            #print B+"\""+str(tmplist)+"\""+M+" is pushed to stack"+RS
        except:
            ##print tmp_list
            #print R+"[ERROR : EMPTY LIST] @ "+nice_offset(p)+G+str(vs).rjust(5)+RS
            #vs.append("FALSE")# PUSH A ERROR ??
            #debug(p)
            #quit()
            fail = 1
    if opcode == 42: #'LISTCAT',
        tmp_list = vs.pop(-1)
        vs.append(tmp_list+vs.pop(-1))
        ##print failmsg+" : "+str(opcode)
    if opcode == 43: #'EVAL',
        print failmsg+" : "+str(opcode)
    if opcode == 44: #'DUMP',
        print failmsg+" : "+str(opcode)
    if opcode == 45: #'NEWENV',
        #for i in range(0, len(sym_ent)):
        #    sl[i].append([])
        ##print R+'NEWENV'
        #sl.append({"pp":ep})
        sl.append([])
        for i in range(0,len(sym_ent)):
            ##print R+sl[-1]
            sl[-1].append("---(n/a)---")
        sl[-1].append(ep)

        ep = len(sl)-1
        #print Y+str(ep)+RS
        ##print sl
        #print M+"new environment: "+str(ep)+" parent :"+str(sl[ep][-1])
    if opcode == 46: #'DEPARTENV'
        ep = sl[ep][-1]
        #print Y+str(ep)+RS
        ##print R+'DEPARTENV'
    if opcode > 46:
        print failmsg+" : "+str(opcode)+" badjump???"

    #if opcode in has_jmp:
    #    print "form :"+nice_offset(tmp_p)+" to :"+nice_offset(p)
    if opcode in has_val and opcode not in has_jmp:
        p += 9
    else:
        p +=1

    if tmp_p in breakpoints:
        #code.interact(local=dict(globals(), **locals()))
        #print R+"BRAKEPOINT @"+nice_offset(tmp_p)
        #for i in range(p-10,p+10):
        #    dis(i)
        #    if i == p:
        #        #print G+"^"*80
        debug(tmp_p)
        cm = raw_input()
        #print cm

        if cm == "s":
            #print "breakpoint set to "+str(p)
            breakpoints.append(p)

    return p


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
    print PB+RS
    print S+"[DEBUGING INFO]".rjust(46,'|')+E.rjust(36,'|')
    print S+Z+"ponter at offset:"+nice_offset(p)+Z+"   next 64-bit: "+enhex(file[p:p+8])+Y+" ep: "+str(ep)+RS
    print S+B+"value stack:"+RS
    for i in range(0, len(vs)):
        print S+B+str(vs[i])+RS
    print Y+"environments:"
    sym_str="   |"
    for x in sym_ent:
        sym_str += str(x).ljust(12)+"|"
    print Y+sym_str+"PARENT".ljust(12)+"|"
    print "-"*len(sym_str)
    for i in range(0,len(sl)):
        env_str = Y+str(i).ljust(3)+"|"
        for x in sl[i]:
            if x == "---(n/a)---":
                env_str+="".ljust(12)+'|'
            else:
                env_str+=str(x)[0:12].ljust(12)+'|'
        print env_str
    print S+"call stack:"
    for i in range(0, len(rs)):
        print S+nice_offset(rs[i])
    print PB+RS

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
