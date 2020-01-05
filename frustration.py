#!/usr/bin/python
# -*- coding: utf-8 -*-
m = [3c, 03, 4c, 8e, cf, 51, 21, fc, 23, 61, 2e, f9, d7, 17, 56, b0]
print "wtf"

for i in range (0, 255):
    d = ''
    for c in range(0, len(m))
        try:
            d+=chr(c+i)
        except:
            d+= "?"
    print d
