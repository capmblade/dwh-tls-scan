#!/usr/bin/python3
#

import sys
import socket
import queue
import threading
import time
import os.path
import datetime
import random
import logging
import getopt

# F5 modules
import dbparam

marker = "./stop"

# Thread management
conn = None
active_threads = { }
thread_num = 0
n_noaddress = 0
iqueue = queue.Queue()
oqueue = queue.Queue()
qceiling = 1000
qwait = 0.5
stay_alive = True

# Database Records
tname = ""
inquery = ""
db_dirty_cnt = 0
updated = 0
foundcount = 0
no_db_write = False

# Other
start_time = 1
debug_log = "_tcpdebug.log"

class TcpThread(threading.Thread):

    def __init__(self,iqueue,oqueue):
        global thread_num
        threading.Thread.__init__(self)
        self.iqueue = iqueue
        self.oqueue = oqueue
        self.tnum = thread_num
        thread_num = thread_num + 1

    def run(self):
        global stay_alive
        while stay_alive:
            if oqueue.unfinished_tasks > qceiling:
                time.sleep(qwait)
                continue
            active_threads[self.tnum] = True
            addr = self.iqueue.get()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            try:
                s.connect((addr,443))
                there = 1
            except:
                there = 0
            s.close()
            oqueue.put((addr,there))
            self.iqueue.task_done()

class UpdateThread(threading.Thread):

    def __init__(self,oqueue,cursor):
        threading.Thread.__init__(self)
        self.oqueue = oqueue
        self.cursor = cursor

    def run(self):
        global conn, db_dirty_cnt, updated, foundcount, no_db_write, tname
        while True:
            (addr,there) = self.oqueue.get()
            #logging.debug("oqueue size = {}".format(oqueue.qsize()))
            if there:
                tt = "TRUE"
                foundcount = foundcount + 1
            else:
                tt = "FALSE"
            if (no_db_write == False):
                u = "UPDATE %s SET last_update = CURRENT_DATE,tcp_there = %s WHERE addr = '%s';" % (tname,tt,addr)
                self.cursor.execute(u)
            db_dirty_cnt = db_dirty_cnt + 1
            updated = updated + 1
            if db_dirty_cnt > 999:
                if (no_db_write == False):
                    conn.commit()
                    logging.info("Commited {} records".format(updated))
                db_dirty_cnt = 0
            self.oqueue.task_done()
    

# This thread resolves the hostname at the same time
class HostTcpThread(threading.Thread):

    def __init__(self,iqueue,oqueue):
        global thread_num
        threading.Thread.__init__(self)
        self.iqueue = iqueue
        self.oqueue = oqueue
        self.tnum = thread_num
        thread_num = thread_num + 1

    def run(self):
        global stay_alive, n_noaddress

        while stay_alive:
            if oqueue.unfinished_tasks > qceiling:
                time.sleep(qwait)
                continue
            active_threads[self.tnum] = True
            foundhost = False

            hostname = self.iqueue.get()

            logging.debug("Looking up %s", hostname)
            try:
                name_entry = socket.gethostbyname_ex(hostname)
                foundhost = True
            except socket.gaierror as err:
                logging.debug("Error %s - Failed to find %s", err, hostname)
                n_noaddress = n_noaddress + 1
            except socket.herror as err:
                logging.error( "gethostbyname failed herror %s", hostname)
            except:
                logging.error( "gethostbyname general exception %s", hostname)

            there = False
            addr = ""
            if foundhost:
                try:
                    addresses = name_entry[2]
                    for addr in addresses:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((addr,443))
                        s.close()
                        there = 1
                except:
                    logging.debug("Address not found for %s", hostname)
            oqueue.put((hostname,addr,there))
            self.iqueue.task_done()
    
class RankUpdateThread(threading.Thread):

    def __init__(self,oqueue,cursor):
        threading.Thread.__init__(self)
        self.oqueue = oqueue
        self.cursor = cursor

    def run(self):
        global conn, db_dirty_cnt, updated, foundcount, no_db_write, tname
        while True:
            (hostname,addr,there) = self.oqueue.get()
            if there:
                tt = "TRUE"
                foundcount = foundcount + 1
            else:
                tt = "FALSE"
            if (no_db_write == False):
                u = "UPDATE {} SET (addr,tcp_there) = ('{}',{}) WHERE hostname = '{}';"
                self.cursor.execute(u.format(tname,addr,tt,hostname))
            db_dirty_cnt = db_dirty_cnt + 1
            updated = updated + 1
            if db_dirty_cnt > 999:
                if (no_db_write == False):
                    conn.commit()
                    logging.info("Commited {} records".format(updated))
                db_dirty_cnt = 0
            self.oqueue.task_done()
    
def main():
    global tname, inquery, no_db_write, conn

    loglvl = logging.INFO
    max_threads = 10
    max_scans = 1000000

    optstring = "b:l:n:t:T:q:Q:rxh?"
    def usage():
        print( "\nUsage: python tcpscan.py -%s" % optstring )
        print( '''
        -b buckets   - Run scan across a bucket or rank
        -l lvl       - set loglevel (DEBUG, INFO, etc) to _tcpdebug.log
        -n count     - Scan only <count> nodes before quitting
        -r           - Resolve hostnames in a rank database
        -t threads   - set the maximum number of threads
        -T tblname   - update table <tblname>
        -x           - do not update the database (diagnostic mode)
        -q query     - operate on records specified by this where query
        -h or -?     - This help
        
        Run a scan on a normal sslscan database
           % python tcpscan.py -q 'ssl_there = 1'
        
        Run a scan on an alexa rank database
           % python tcpscan.py -r -T a_2017q1 -b 200,000-350k
        
        See README.md for more help
        ''')

    try:
        opts, args = getopt.getopt(sys.argv[1:], optstring)
    except getopt.GetoptError as err:
        print ( str(err) )
        usage()
        sys.exit(1)

    rank_db = False
    use_buckets = False
    bucket_start = 0 # can be single bucket or start of range
    bucket_end = 0   # if 0, then we're using single bucket
    MAX_BUCKET = 100000000

    for o,a in opts:
        if o == "-n":
            max_scans = decode_number(a)
            print( "Setting max scan to %d" % max_scans )
        elif o in ("-h", "--help", "-?"):
            usage()
            sys.exit(0)
        elif o == "-b":
            use_buckets = True
            n = a.find('-')
            if n == -1:
                bucket_start = decode_number(a)
            else:
                bucket_start = decode_number(a[0:n])
                bucket_end = decode_number(a[n+1:])
        elif o == "-m":
            print( "MySQL support is depecrated" )
            sys.exit(1)
        elif o == "-r":
            rank_db = True
        elif o == "-x":
            no_db_write = True
        elif o == "-t":
            max_threads = int(a)
            print( "Setting max threads to %d" % max_threads )
        elif o == "-T":
            tname = a
        elif o == "-q":
            inquery = a
        elif o == "-l":
                    n = getattr(logging, a.upper(), None)
                    if not isinstance(n, int):
                            raise ValueError('Invalid log level: %s' % a)
                    loglvl = n
        else:
            assert False, "unhandled option %s" % o

    if len( tname ) == 0:
        print( "Need a table name (-T). See -h for help" )
        sys.exit(1)

    if rank_db:
        if tname == "":
            print( "Need a database name for the rank database" )
            sys.exit(1)

        if use_buckets and (bucket_start > MAX_BUCKET or bucket_end > MAX_BUCKET or \
            bucket_end <= bucket_start):
            print( "Bucket range {}-{} invalid. Must be 1-{}".format(
                    bucket_start, bucket_end, MAX_BUCKET) )
            sys.exit(1)
    else:
        if use_buckets and (bucket_start > 99 or bucket_end > 99 or \
            bucket_end <= bucket_start):
            print( "Bucket range {}-{} invalid. Must be 0-99".format(bucket_start, bucket_end) )
            sys.exit(1)

    logging.basicConfig(level=loglvl,filename=debug_log)
    logging.info(" --- NEW START -- : {}".format( time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())))

    if (max_scans < max_threads):
        max_threads = max_scans

    try:
        print( "Starting TCP Scan: %d Max Threads" % max_threads )
        if os.path.isfile(marker):
            os.remove(marker);
        conn = dbparam.connect()
        logging.debug( "Connected to Database" )
    except:
        print( "Error: {}".format( sys.exc_info()[0] ))
        logging.error( "Cannot connect to server - error: {}".format(sys.exc_info()[0]))
        sys.exit(1)

    # get the list of addresses that don't have a tcp value
    cursor = conn.cursor()

    if rank_db:
        if (len(inquery)):
            q = "SELECT hostname FROM {} WHERE {}".format(tname, inquery)
        else:
            q = "SELECT hostname FROM {} WHERE tcp_there IS NULL".format(tname)
    else:
        if (len(inquery)):
            q = "SELECT addr FROM {} WHERE {}".format(tname, inquery)
        else:
            q = "SELECT addr FROM {} WHERE tcp_there IS NULL".format(tname)

    if use_buckets:
        if (bucket_end == 0):
            if rank_db:
                print( "Rank db needs a bucket end." )
                sys.exit(1)
            q = q + " AND rank = {}".format(bucket_start)
        else:
            if rank_db:
                q = q + " AND rank BETWEEN {} AND {}".format(bucket_start, bucket_end)
            else:
                q = q + " AND bucket BETWEEN {} AND {}".format(bucket_start, bucket_end)

    if (max_scans != 0):
        q = q + " LIMIT {}".format(max_scans)

        logging.info("Query Set: {}".format(q))
    cursor.execute(q)
    dbrows = cursor.fetchall()
    cursor.close()

    logging.info("Initial Row List is {}".format(len(dbrows)))

    rows = []
    logging.debug("Translate rows into list" )
    for row in dbrows:
        rows.append(row[0])

    dbrows = [] # free all that memory?

    for row in rows:
        iqueue.put(row)

    for x in range(max_threads):
        if rank_db:
            t = HostTcpThread(iqueue,oqueue)
        else:
            t = TcpThread(iqueue,oqueue)
        t.setDaemon(True)
        t.start()

    cursor = conn.cursor()
    if rank_db:
        t = RankUpdateThread(oqueue,cursor)
    else:
        t = UpdateThread(oqueue,cursor)
    t.setDaemon(True)
    t.start()

    start_time = int(time.time()) - 1
    qlen0 = iqueue.unfinished_tasks
    while ((qlen0 - iqueue.unfinished_tasks) < max_scans):
        if os.path.isfile(marker):
            break
        time.sleep(5)
        if (iqueue.unfinished_tasks == 0):
            break;

        ustring = "Threads |"
        for i in range(max_threads):
            if active_threads[i] == True:
                ustring = ustring + "A"
                active_threads[i] = False
            else:
                ustring = ustring + "_"
        q = iqueue.unfinished_tasks
        qo = oqueue.unfinished_tasks
        elapsed = int(time.time()) - start_time

        if elapsed > 0 and updated > 0:
            rate = updated / elapsed
            tleft = iqueue.unfinished_tasks / max(1, rate)
            d = datetime.datetime(1,1,1) + datetime.timedelta(seconds=tleft)
            tn = "{}:{:02}:{:02}:{:02}".format(d.day-1, d.hour, d.minute, d.second)
            print( "TCPSCAN {} q={:,} o={} f={:.2%} {:>3}/s {}|".format(tn, q, qo,
                    float(foundcount)/updated, int((qlen0-q)/elapsed), ustring) )

    if os.path.isfile(marker):
        stay_alive = False
        print( "File stopper detected, ending!" )

    # If this is a problem then you forgot to index on addr
    qo = oqueue.unfinished_tasks
    while (qo > 0):
        tn = datetime.datetime.now().strftime("%H:%M:%S")
        print( "TCPSCAN {} - Draining Output, index by addr???: {}".format(tn,qo) )
        time.sleep(5)
        qo = oqueue.unfinished_tasks

    if (db_dirty_cnt > 0) and (no_db_write == False):
        print( "Committing Changes..." )
        conn.commit()
    conn.close()
    logging.debug( "Disconnected" )
    print( "{} Hosts Founds and {} Records Updated".format(foundcount, updated) )
    print( "Completed scan in {} seconds".format( int(time.time()) - start_time ) )

if __name__ == '__main__':
    sys.exit(main())

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
