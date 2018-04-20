#!/usr/bin/python3
#
# Random Hosts
#
# Read giant input file from Project Sonar file.
# Filter out smaller, random number of lines
# By default we do 5%

import os
import sys
import getopt
import random
import fileinput
import subprocess
from dbparam import *

# Command options
infile = ""
create = False
total = 0
marker = "./stop"
le = 0

n_string = '5%'

def usage(args):

    print()
    print("{} [-n[%]] -o".format(args[0]))
    print('''
Options
    -n max[%] only import 'max' new lines
    -e lines  estimate of the number of lines in the input file

Filter out a subset from input file. Estimate size of input, start randomly
within 100 lines, then skip consistent number of lines, output a line, repeat.

Specifically for Project Sonar 'hosts' file. The hosts files are quite
large, estimated to be around 25M lines.

'n' can be a percentage of 'hosts', like so:

python randomhosts.py -n 10% 20150401_hosts > 201504_subset
''')
    sys.exit(1);

optstring = "h?e:n:"

try:
    opts, args = getopt.getopt(sys.argv[1:], optstring)
except getopt.GetoptError as err:
    print(str(err))
    usage(sys.argv)
    sys.exit(1)

for o,a in opts:
    if o == "-n":
        n_string = a
    elif o == "-e":
        le = decode_number(a)
    elif o in ("-h", "--help", "-?"):
        usage(sys.argv)
        sys.exit(0)
    else:
        assert False, "unhandled option %s" % o

# Get the number of total rows (or the guess)
if le > 0:
    nrows = le
else:
    spo = subprocess.Popen("wc -l {}".format(args[0]),stdout=subprocess.PIPE,shell=True).stdout.read()
    nrows = int(spo.decode('utf-8').split(' ')[0])

sys.stderr.write("\nLine Esimate {}\n".format(nrows))

# Get the number of rows that we want to keep
if '%' in n_string:
    n = (nrows * int(n_string.strip('%'))) / 100
else:
    n = decode_number(n_string)

if n > nrows:
    sys.stderr.write( "Too many rows requested" )
    sys.exit(2)
elif n == 0:
    sys.stderr.write( "invalid input {}".format(n_string) )
    sys.exit(2)
elif n == nrows:
    interval = 1
else:
    interval = int((nrows - 100) / n)

sys.stderr.write( "Pulling {} lines from input.\n".format(n) )

random.seed()
# skip randomly into the first 100, read 'interval' after that
count = int(random.random() * 100) + 1

fin = open(args[0], 'r')

for line in iter(fin):
    if (count % interval) == 0:
        print(line.rstrip())
    count = count + 1

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
