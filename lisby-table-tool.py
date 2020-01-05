#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import sys

'''--------------------------------------------------------------------------'''
def fail():
    print 'usage ./lisby-table-tool.py file-name'
    quit()

o_cw = 10  #offset cell width
i_cw = 8  #index cell width
l_cw = 10 #length cell width
c_cw = 40 #content cell width
tt = "┏"+"─"*o_cw+"┯"+"─"*i_cw+"┯"+"─"*l_cw+"┯"+"─"*c_cw+"┓"  #top table
ht = "┣"+"═"*o_cw+"┿"+"═"*i_cw+"┿"+"═"*l_cw+"┿"+"═"*c_cw+"┫"  #header table
mt = "┣"+"─"*o_cw+"┿"+"─"*i_cw+"┿"+"─"*l_cw+"┿"+"─"*c_cw+"┫"  #middle table
bt = "┗"+"─"*o_cw+"┷"+"─"*i_cw+"┷"+"─"*l_cw+"┷"+"─"*c_cw+"┛"  #bottom table

def tablefi(o,i,l,c):
        print "│ "+str(o).ljust(o_cw-1)+'│ '+str(i).ljust(i_cw-1)+'│ '+str(l).ljust(l_cw-1)+'│ '+str(c).ljust(c_cw-1)+"│"

def debug(pointer):
    print "ponter at offset:"+hex(pointer)+"   next 64-bit: "+enhex(file[pointer:pointer+8])

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
            entry_hex=''.join(x.encode('hex') for x in entry_contents)
            #tablefi(hex(pointer),i,entry_length,entry_hex)
            tablefi(hex(pointer),i,entry_length,entry_contents.replace('\x0a', '\\n'))
            entries.append(entry_contents)
            pointer += entry_length
            #pointer += entry_length+1 #ending with \x00??
        print bt
    return {'pointer':pointer, 'entries':entries}

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
print "*"*80
print(" ".join("LISBY DEVICE : STRING AND SYMBOL TABLE"))
print "*"*80+"\n"
p = 8 # set pointer to 8 to skip magicprefix

print "STRING TABLE"
str_tbl = par_tbl(p)
p = str_tbl['pointer']
str_ent=str_tbl['entries']

print "-"*80
#debug(p)
print "-"*80
print "SYMBOL TABLE "
sym_tbl = par_tbl(p)
p = sym_tbl['pointer']
str_ent=sym_tbl['entries']
print "-"*80
