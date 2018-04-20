#!/usr/bin/python3
#
# connection functions for database.
#
# Edit the dwh-tls-scan.ini file to include your database info

import psycopg2
import configparser
from time import localtime, time

dbini = 'dwh-tls-scan.ini'

def connect ( mysql=True ):
    config = configparser.ConfigParser()
    if config.read( dbini ) == []:
        raise Exception( 'Cannot find initialization file, {}'.format(dbini) )

# The postgres hostname and password will be picked up from .pgpass
    return psycopg2.connect(
            database=config['POSTGRES']['db_name'],
            user=config['POSTGRES']['user_name'],
            password=config['POSTGRES']['password'],
            host=config['POSTGRES']['host'] )

def crt_connect():
    return psycopg2.connect( database='certwatch', user='guest',
            host='crt.sh', port=5432)

def dbname():
    config = configparser.ConfigParser()
    if config.read( dbini ) == []:
        raise Exception( 'Cannot find initialization file, {}'.format(dbini) )

# The postgres hostname and password will be picked up from .pgpass
    return config['POSTGRES']['db_name']

# Create a databse name based on today's date.
# Something like i_2016Q3
def mkname(prefix="i_"):
	q = 4
	lt=localtime( time() )
	if lt.tm_mon < 4:
		q = 1
	elif lt.tm_mon < 7:
		q = 2;
	elif lt.tm_mon < 10:
		q = 3;

	return "{}{}q{}".format( prefix, lt.tm_year, q )

def decode_number(aa):
    a = aa.replace(',','')
    mult = { 'k':1000, 'K':1000, 'm':1000000, 'M':1000000, 'b':1000000000, 'B':1000000000 }
    m = 1
    l = 0
    for i in a:
        l = l + 1
        if i not in '0123456789':
            try:
                m = mult[i]
                return int(a[:l-1]) * m
            except:
                print( "Unrecognized number modifier '{}', must be 'k,m or b'" )
                raise

    return int(a)
		
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
