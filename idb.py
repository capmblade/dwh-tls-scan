#!/usr/bin/python3

import os
import sys
import getopt
import subprocess
import logging

# F5 modules
import dbparam

debug_log  = "./_debug.log"
# Feb 23 2017
# 
# Assume PostGres from now on.
#   

def banner(args):
    print( "%s -- Initialize the scan SSL database." % args[0] )

def usage(args):
    print
    print( "%s [-I or -r] [-l loadfile] [tbl_name]" % args[0] )
    print( ''' 
Options
    -I           Initialize a new SSL scan database
    -r           Generate a hostname database (just hostnames, rank, address, tcp_there)
    -l loadfile  Read in an alexa-type file into the database.
    -h           This help.

Creates the scanner table and indices. There are three ways to do this. For mass-scan
Project Sonar files, use -I. -r creates a 'rank' database, into which you load an
opendns or Alexa file. 

See README.md for more. 


Examples

% python idb.py -I tmpXXX

  ^ The default table name is based on the current quarter and looks
    like this: i_2016Q4. You may provide your own custom table name
    as the last parameter.

    If the table exists, an error will occur.

% python idb.py -r -l ../hosts/alexa_1m.csv a_2016q3 

  ^ Create a rank database a_2016q3 and read the file alexa_1m.csv into it.

''')

# temp sequence for buckets
seq_cmd = '''
CREATE SEQUENCE {}_bkt START 1 MAXVALUE 99 CYCLE;
'''

# SSL Scan Database definition
#
init_cmd = '''
CREATE TABLE {}
(
    addr CHAR(15) NOT NULL PRIMARY KEY,
    orig_hash CHAR(40),
    last_update DATE,
    tcp_there BOOL,
    bucket SMALLINT NOT NULL DEFAULT nextval('{}_bkt'),
    ssl_there BOOL,
    ssl_subject TEXT,
    ssl_issuer TEXT,
    ssl_issuer_oname CHAR(45),
    ssl_self_signed BOOL,
    ssl_protocol CHAR(20),
    ssl_cipher TEXT,
    ssl_pksize INT,
    ssl_timeout INT,
    ssl_session_id1 TEXT,
    ssl_session_id2 TEXT,
    ssl_v3 BOOL,
    ssl_pfs BOOL,
    ssl_ext_heartbeat BOOL,
    ssl_ext_reneg_sec BOOL,
    ssl_ext_tickets BOOL,
    ssl_hsts BOOL,
    ssl_server_string TEXT,
    ssl_is_bigip BOOL,
    ssl_is_akamai BOOL,
    ssl_is_cloudflare BOOL,
    altered_by CHAR(25),
    alexa_rank INT,
    hostname VARCHAR(255),
    ssl_probe_result VARCHAR(255),
    ssl_rsa BOOL,
    ssl_temp_key CHAR(60)
);
'''

idx_columns = (
    'addr',  # need this for tcpscan AND sslscan updates
    'tcp_there',
    'ssl_there',
    'alexa_rank',
    'ssl_is_bigip',
    'ssl_is_akamai',
    'ssl_is_cloudflare',
    'ssl_server_string' )

# postgres version...
create_idx_cmd = "CREATE INDEX ON {} ({});"

# Rank Database definition
rankdb_init_cmd = '''
CREATE TABLE {}
(
    rank INT NOT NULL,
    hostname VARCHAR(255),
    tcp_there BOOL,
    addr CHAR(15)
);
'''

create_rank_idx_cmd = "CREATE INDEX ON {} ({});"

# -I and -T are the same
optstring = "h?Il:mprT"

def just_connect():
    try:
        conn = dbparam.connect(False);
        print( "connected!" )
    except MySQLdb.Error as e:
        print( "Cannot connect to database server" )
        print( "Error code: ", e.args[0] )
        print( "Error message:", e.args[1] )
        sys.exit(1)
    return conn

def connect_and_check(dbname):

    conn = just_connect()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_name='{}';".format(dbname))
        r1 = cursor.fetchone()
        if len(r1) > 0:
            print( 'Table {} already exists. Aborting.'.format(dbname) )
            sys.exit(1)
    except:
        print( "Table {} not found in database".format(dbname) )
    cursor.close()
    return conn

def create_sslscan_database(dbname):

    conn = connect_and_check(dbname)
    cursor = conn.cursor();

    cmd = seq_cmd.format(dbname)
    print( cmd )
    cursor.execute(cmd)

    cmd = init_cmd.format(dbname,dbname)
    print( cmd )
    cursor.execute(cmd);

    for i in idx_columns:
        idx = create_idx_cmd.format(dbname, i)
        print( idx )
        cursor.execute(idx)

    owned_cmd = "ALTER SEQUENCE {}_bkt OWNED BY {}.bucket;"
    cmd = owned_cmd.format(dbname, dbname)
    cursor.execute(cmd)

    cursor.close();
    print( "Comitting" )
    conn.commit();
    conn.close();
    print( "Done" )

def create_rank_database(conn, dbname, allowExisting=False):

    cursor = conn.cursor()
    cmd = rankdb_init_cmd.format(dbname)
    print( cmd )
    e = cursor.execute(cmd);

#   Create index on hostname
    idx = create_idx_cmd.format(dbname, "hostname")
    print( idx )
    cursor.execute(idx)

    cursor.close()
    conn.commit();
    return e

def load_rank_file(conn, tname, loadfile):

    dbname = dbparam.dbname()

    if ".z" in loadfile or ".gz" in loadfile:
        cat = 'zcat'
    else:
        cat = 'cat'

    print( "Loading rank file {}".format(loadfile))
    p1 = subprocess.Popen( [ cat, loadfile ], stdout = subprocess.PIPE)
    p2cmd = "COPY {} (rank,hostname) FROM stdin WITH DELIMITER ',';".format(tname)
    p2 = subprocess.Popen( [ 'psql', dbname, '-c', p2cmd ],
            stdin=p1.stdout, stdout=subprocess.PIPE )
    p2out = p2.communicate()

    print( "Done Loading" )

def main(argv):
    tname = ""
    MODE_NONE = 0
    MODE_INITDB = 1
    MODE_RANKDB = 2
    MODE_CRTSH = 3

    mode = MODE_NONE
    create_rankdb = False

    banner(argv)

    loadfile = ""

    logging.basicConfig(level=logging.INFO,filename=debug_log)

    try:
        opts, args = getopt.getopt(argv[1:], optstring)
    except getopt.GetoptError as err:
        print( str(err) )
        usage(sys.argv)
        sys.exit(1)

    for o,a in opts:
        if o == "-I" or o == "-T":
            mode = MODE_INITDB
        elif o == "-r":
            mode = MODE_RANKDB
        elif o == "-l":
            loadfile = a
        elif o == "-m":
            print( "MySQL no longer supported" )
            sys.exit(2)
        elif o == "-p":
            postgres = True
        elif o in ("-h", "--help", "-?"):
            usage(sys.argv)
            sys.exit(0)
        else:
            assert False, "unhandled option %s" % o

    if len(args) == 0:
        if create_rankdb:
            usage(sys.argv)
            print( "\nNeed name for rank database" )
            sys.exit(1)
        tname = dbparam.mkname()
    else:
        tname = args[0]

    print( "Using Database name: {}".format(tname) )

    if mode == MODE_RANKDB:
        conn = just_connect()
        create_rank_database(conn, tname)
        
        if len(loadfile) > 0:
            load_rank_file(conn, tname, loadfile)

    elif mode == MODE_INITDB:
        create_sslscan_database(tname)

    else:
        usage(sys.argv)
        sys.exit(1)

    print( "Done" )

if __name__ == '__main__':
    sys.exit(main(sys.argv))

