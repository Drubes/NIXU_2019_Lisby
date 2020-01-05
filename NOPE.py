#!/usr/bin/python
from pwn import *
import sys

def fail():
    print 'usage ./lisby-table-tool.py file-name'
    quit()


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

print 'ok here we go!!'



print 'offset'.ljust(8)+'|'+'Unpacked'.ljust(20)+'|'+'charcter'
#print 'offset'.ljust(8)+'|'+'RAW'.ljust(20)+'|'+'Unpacked'.ljust(20)+'|'+'charcter'
for i in range(0, len(file)/9):
    chunk = file[(i*8)+1:(i*8)+9]

    unpacked = u64(chunk)
    try:
        char = unichr(unpacked)
    except:
        char = '---'
    if unpacked == 0x313030594253494c or unpacked == 0x4953425930303100:
        char = 'MAGIC'

    print hex(i*8).ljust(8)+'|'+str(unpacked).ljust(20)+'|'+char

#    print "oops"
#    quit()




'''
str_table_length = u64(file[8:16])
print " String table  -- entries:"+str(str_table_length)
print tt
tablefi("index","length","content")
print mt
pointer = 16




sym_table_length = u64(file[pointer:pointer+8])
pointer +=8
print "symbol table entries:"+str(sym_table_length)
print "index".ljust(5)+" | "+"length".ljust(10)+" | "+"content".ljust(20)

print '-'*80
for i in range(0,sym_table_length):
    entry_length = u64(file[pointer:pointer+8])
    pointer += 8
    entry_contents =  file[pointer:pointer+entry_length]
    #entry_hex=''.join(x.encode('hex') for x in entry_contents)
    entry_hex = enhex(entry_contents)
    pointer += entry_length
    print str(i).ljust(5)+' | '+str(entry_length).ljust(10)+' | '+entry_hex

'''
'''
-------------------------------------------------------------------------------
offset = 0
while offset < 9:
    p = offset
    while 1:
        try:
            raw = file[p:p+8]
            unpacked = u64(raw)
            rawhex = hex(unpacked)
            print hex(p).ljust(10)+':  '+hex(unpacked).ljust(20)+" | "+enhex(raw)
            p += 8+offset
        except:
            print str(offset)+' - DONE'
            break
    offset +=1
    raw_input()
'''
