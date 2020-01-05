#!/usr/bin/python
import zlib


mangled = [54, 158, 210, 108, 250, 24, 82, 12, 90, 93, 123, 192, 23, 162, 82,
           89, 201, 130, 13, 18, 7, 198, 213, 228, 138, 243, 212, 62, 80, 118,
           87, 170]
flag =    [96, 222, 148, 50, 199, 45, 43, 103, 51, 59, 23, 218, 119, 254, 15,
           44, 169, 30, 88, 125, 113, 166, 167, 151, 251, 179, 169, 86, 35, 23,
           116, 212]

zipped = [170, 212, 87, 116, 118, 23, 80, 35, 62, 86, 212, 169, 243, 179, 138,
          251, 228, 151, 213, 167, 198, 166, 7, 113, 18, 125, 13, 88, 130, 30,
          201, 169, 89, 44, 82, 15, 162, 254, 23, 119, 192, 218, 123, 23, 93,
          59, 90, 51, 12, 103, 82, 43, 24, 45, 250, 199, 108, 50, 210, 148,
          158, 222, 54, 96]
zippedhex= "aad45774761750233e56d4a9f3b38afbe497d5a7c6a60771127d0d58821ec9a9592c520fa2fe1777c0da7b175d3b5a330c67522b182dfac76c32d2949ede3660"
'''

for i in range(0,255):
    test = unichr(zipped[0]-i)
    #print test
    if test == "N":
        print "YES"+str(i)
        break
for i in range(0,255):
    test = unichr(zipped[1]-i)
    #print test
    if test == "I":
        print "YES"+str(i)
        break
for i in range(0,255):
    test = unichr(zipped[2]+i)
    #print test
    if test == "X":
        print "YES"+str(i)
        break
'''
for i in range(1,10000):
    test=""
    for x in zipped:
        test += unichr(x%i)
    print test
