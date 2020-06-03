#! /usr/bin/env python3
''' brute force indentation for the raw plugin traces'''
import sys

indent = 0
with open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin as fd:
   line=fd.readline()
   while line:
       print("{}{}".format(" "*indent, line.strip()))
       if line.startswith("ENTRY"):
           indent+=1
       if line.startswith("EXIT"):
           indent-=1
       line=fd.readline()
