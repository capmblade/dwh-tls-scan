#!/usr/bin/python3
#
# The SSL Scanner - Multithreaded Python / MySQL module
#
# See README.md for toolset
# 
# python3 sslscan.py -h for help
#

import sys
import os
import subprocess
import getopt
import select
import queue
import threading
import time
import datetime
import logging
import random
import socket
import signal
import traceback

# F5 Scanner modules
import dbparam

optstring = "a:b:cdDhl:n:p:Ps:t:T:q:Q:xX?"

# Update "not there"
unt = '''
UPDATE {} SET
    last_update = CURRENT_DATE,
    altered_by='{}',
    ssl_there=False
    WHERE addr = '{}';
'''

tname = dbparam.mkname()

# SSL
MIN_OPENSSL_VERSION = "OpenSSL 1.1."
sclient_proto = ""

# Diagnostics
dump_lines = False
dump_ts = False
dump_commit = False
bad_probes = 0
exceptions = 0
scan_total = 0
commit_log = "./_dbcommit.log"
debug_log  = "./_debug.log"
thishost = ""
loglvl = logging.INFO
foundcount = 0
updated = 0
db_dirty_cnt = 0
strip_chars = ' \t\r\n\0'
bstrip_chars = b' \t\r\n\0'

# Threading
g_env = os.environ.copy()
nodata_sleep = 0.25
nodata_max = 5
sleep_time = 0.25
max_threads = 25
max_scans = 1000000
thread_num = 0
marker = "./stop"
no_db_write = False
dirty_commit = 99
stay_alive = True
process_timeout = 30
l_active = {}
l_pids   = {}
l_addrs  = {}
l_times  = {}
g_port = 443

# Database
conn = None
iqueue = queue.Queue()
oqueue = queue.Queue()
getcmd = "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n"
headcmd = "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n"
tlsargs = [ "openssl", "s_client", "-ign_eof" ]
inquery = ""

def isipaddr( s ):
    for i in s:
        if i not in ".0123456789":
            return False
    return True

class TlsStats:
    ''' TlsStats class represents only the statistics associated to a single host '''
    def __init__(self,list_ah):
        self.addr = list_ah[0].strip()
        self.hostname = list_ah[1]
        self.success = False
        self.subject = ""
        self.issuer = ""
        self.self_signed = False
        self.protocol = ""
        self.cipher = ""
        self.pksize = 0
        self.timeout = 0
        self.session1 = ""
        self.session2 = ""
        self.ext_heartbeat = False
        self.ext_secure_reneg = False
        self.ext_tickets = False
        self.insecure_reneg = False
        self.certificate = ""
        self.hsts = False
        self.server_string = ""
        self.is_bigip = False
        self.is_akamai = False
        self.is_cloudflare = False
        self.ssl3 = False
        self.pfs = False
        self.rsa = False
        self.fs_key = ""
        self.need_ssl3_check = True
        self.need_pfs_check = True

    def hna(self):
        if self.hostname and len(self.hostname):
            return self.hostname
        return self.addr

    def get_issuer_oname(self):
        s = self.issuer;
        if s is None or len(s.strip()) == 0:
            return ""

        n = s.find('O = ')
        if n > 0:
            s = s[n+4:]
            if s[0] == '"':
                s = s[1:]
                e = s.find('"')
            else:
                e = s.find(',')
            # if CA name contains multi-byte characters we're going to get some garbage like this
            # 'O = "MarketWare - Solu\C3\A7\C3\B5es para Mercados Digitais, Lda."
            # which will exceed our buffer. In that case, just chop at first space
            s = s[:e]
            if len(s) > 45 or s.find('\\') > 0:
                e = s.find(' ')
                if e == -1:
                    e = 44
                s = s[:e]
            return s
        else:
            logging.info( "Cannot parse org out of issuer: {} {}".format(self.addr, s))
            return "Unknown"

    def build_update(self, tname, whodidit):
        # Build the database update string and pray to god that someone didn't
        # put an SQLi in this input. I suppose they could have done so in the
        # certificate subject and issuer, but I properly escaped those, right?

        if not self.rsa and not self.pfs:
            # This can happen if the server accepts SSL but then stalls
            # on the HTTP response. Example cn1.client.akadns.net
            logging.warning( "addr {} has neither PFS nor RSA: {}".format(self.addr, self.hostname))
        u = "UPDATE {} SET last_update=CURRENT_DATE,".format(tname)
        u = u + "altered_by='{}',ssl_there={},".format(whodidit, self.success)
        u = u + "ssl_subject=$${}$$,ssl_issuer=$${}$$,".format(self.subject, self.issuer)
        u = u + "ssl_issuer_oname=$${}$$,".format( self.get_issuer_oname())
        u = u + "ssl_self_signed={},".format(self.self_signed)
        u = u + "ssl_protocol='{}',ssl_cipher='{}',".format(self.protocol, self.cipher)
        u = u + "ssl_v3={},ssl_pfs={},ssl_rsa={},".format(self.ssl3,self.pfs,self.rsa)
        u = u + "ssl_pksize={},ssl_timeout={},".format(self.pksize, self.timeout)
        u = u + "ssl_session_id1='{}',".format(self.session1)
        u = u + "ssl_session_id2='{}',".format(self.session2)
        u = u + "ssl_temp_key='{}',".format(self.fs_key)
        u = u + "ssl_ext_heartbeat={},".format(self.ext_heartbeat)
        u = u + "ssl_ext_tickets={},".format(self.ext_tickets)
        u = u + "ssl_ext_reneg_sec={},".format(self.ext_secure_reneg)
        u = u + "ssl_hsts={},".format(self.hsts)
        u = u + "ssl_server_string=$${}$$,".format(self.server_string)
        u = u + "ssl_is_bigip={},".format(self.is_bigip)
        u = u + "ssl_is_akamai={},".format(self.is_akamai)
        u = u + "ssl_is_cloudflare={}".format(self.is_cloudflare)
        u = u + " WHERE addr = '{}';".format(self.addr)
        return u

class TlsScanThread(threading.Thread):

    def __init__(self,iqueue=None,oqueue=None):
        global thread_num
        threading.Thread.__init__(self)
        self.tnum = thread_num
        self.iqueue = iqueue
        self.oqueue = oqueue

    def build_cmdlist(self, extralist=None):
        global g_port
        cmdlist = tlsargs + [ "-connect" ] + [ "{}:{}".format( self.ts.addr, g_port) ]
        if self.ts.hostname and len(self.ts.hostname):
            cmdlist = cmdlist + [ '-servername' ] + [ self.ts.hostname ]
        if extralist:
            for e in extralist:
                cmdlist = cmdlist + [ e ]
        return cmdlist

    # python3 is really strict about unicode/utf-8/bytes vs text.
    # When we call readline() we get a bytes string back, but we're 
    # actually looking for english ASCII text. Handle the exceptions.
    # 
    def readline_decode(self,fd):
        b = fd.readline().rstrip(bstrip_chars)
        try:
            text = b.decode(errors='ignore')
        except UnicodeDecodeError as e:
            logging.debug( "UnicodeDecodeError: Server {}: {} - {}",
                self.hna(), type(e), e.args)
            return ""
        return text

    def hna(self):
        if self.ts.hostname and len(self.ts.hostname):
            return self.ts.hostname
        return self.ts.addr

    # If we get a DH connection then we know that we have PFS
    # support and we don't have to explicitly test for that later
    # (note this relies on s_client prioritizing DH clients first)
    def scan_first(self):
        logging.debug("scan_first starting: %s" % self.ts.hna())
        cmdlist = self.build_cmdlist()

        logging.debug("- executing {}".format( cmdlist ))
        if dump_lines:
            print('-- SCAN FIRST ---')
            print('-- {}'.format(cmdlist))
            print('--')

        p = subprocess.Popen(
            cmdlist,
            env=g_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        l_pids[self.tnum]  = p.pid
        l_addrs[self.tnum] = self.ts.addr
        l_times[self.tnum] = int(time.time())

        request = headcmd.format(self.hna()).encode()
        if dump_lines:
            print( "\n{}\n".format( request ))
            logging.debug( request )
        p.stdin.write( request )
        line = self.readline_decode(p.stdout)
        p.stdin.close()

        matched = False
        dead_already = False
        nodata = 0
        poll_obj = select.poll()
        poll_obj.register(p.stdout, select.POLLIN)

        while nodata < nodata_max:
            line = ""
            if poll_obj.poll(0):
                line = self.readline_decode(p.stdout)
                if len(line) > 0:
                    nodata = 0
                else:
                    nodata = nodata + 1
                    continue
                if dump_lines == True:
                    print( line )
                    logging.debug("LINE {}: {}".format(self.hna(),line))
            elif p.poll() is not None:
                dead_already = True
                l_pids[self.tnum] = 0
                break
            else:
                nodata = nodata + 1
                time.sleep(nodata_sleep)
                continue

            matched = True;
            if line[0:33] == "Secure Renegotiation IS supported":
                self.ts.ext_secure_reneg = True
            elif line[0:8] == "subject=":
                self.ts.subject = line[8:].replace('$',r'').strip(strip_chars)
                if len(self.ts.subject) and self.ts.subject[0] == '/':
                    self.ts.subject = self.ts.subject[1:]
            elif line[0:7] == "issuer=":
                self.ts.issuer = line[7:].replace('$',r'').strip(strip_chars)
                if len(self.ts.issuer) and self.ts.issuer[0] == '/':
                    self.ts.issuer = self.ts.issuer[1:]
            elif line[0:21] == "Server public key is ":
                self.ts.pksize = int(line[21:25])
            elif line[0:16] == "    Protocol  : ":
                self.ts.protocol = line[16:]
                if self.ts.protocol == "SSLv3":
                    self.ts.ssl3 = True
                    self.ts.need_ssl3_check = False
                if self.ts.protocol == "TLSv1.3":
                    self.ts.pfs = True
                    self.ts.need_pfs_check = False
            elif line[0:16] == "    Cipher    : ":
                self.ts.cipher = line[16:]
                if self.ts.cipher.find("DH") != -1:
                    self.ts.pfs = True
                    self.ts.need_pfs_check = False;
                if self.ts.cipher == '0000':
                    matched = False
                    # Only set false here on the first scan
                    self.ts.success = False
                    logging.debug("Cipher 0000, very likely accpeting TCP but not SSL/TLS: {} {}".format(
                    self.ts.addr, self.ts.hostname))
                    break
            elif line[0:17] == 'Server Temp Key: ':
                self.ts.fs_key = line[17:]
            elif line[0:36] == "    TLS session ticket lifetime hint":
                self.ts.ext_tickets = True
            elif line[0:16] == "    Timeout   : ":
                self.ts.timeout = int(line[16:19])
            elif line[0:16] == "    Session-ID: ":
                self.ts.session1 = line[16:]
            elif line[0:8] == "Server: ":
                # line = line.decode('utf-8',errors='ignore').encode("utf-8")
                self.ts.server_string = line[8:].replace('$',r'').strip(strip_chars)
                if self.ts.server_string.find('Akamai') != -1:
                    self.ts.is_akamai = True
                elif self.ts.server_string.find('cloudflare') != -1:
                    self.ts.is_cloudflare = True
                elif self.ts.server_string.lower().find('bigip') != -1:
                    self.ts.is_bigip = True
            elif line[0:27] == "Strict-Transport-Security: ":
                self.ts.hsts = True
            else:
                matched = False;

            if matched == True:
                self.ts.success = True

        # out of while loop
        if self.ts.success == True:
            if (len(self.ts.subject) > 0) and (self.ts.subject==self.ts.issuer):
                self.ts.self_signed = True
            if not self.ts.pfs:
                self.ts.rsa = True

        if dead_already == False:
            p.terminate()
            l_pids[self.tnum] = 0

        logging.debug("scan_first({} {}) complete: {}".format(
            self.ts.addr, self.ts.hostname, self.ts.success))

    # The second connection will try to pick up a few more details like
    # session tickets by turning on the -tlsextdebug flag
    def scan_second(self):
        logging.debug("scan_second starting: %s" % self.ts.hna())
        if 'TLS' in self.ts.protocol:
            cmdlist = self.build_cmdlist( ["-tlsextdebug"] )
        else:
            cmdlist = self.build_cmdlist()

        logging.debug("- executing {}".format( cmdlist ))
        if dump_lines:
            print('-- SCAN SECOND ---')
            print('-- {}'.format(cmdlist))
            print('--')

        p = subprocess.Popen(
            cmdlist,
            env=g_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        l_pids[self.tnum]  = p.pid
        l_addrs[self.tnum] = self.ts.addr
        l_times[self.tnum] = int(time.time())

        request = getcmd.format(self.hna()).encode()
        if dump_lines:
            print( "\n{}\n".format( request ))
            logging.debug( request )
        p.stdin.write( request )
        line = self.readline_decode(p.stdout)
        p.stdin.close()

        dead_already = False
        nodata = 0
        poll_obj = select.poll()
        poll_obj.register(p.stdout, select.POLLIN)

        while nodata < nodata_max:
            line = ""
            if poll_obj.poll(0):
                line = self.readline_decode(p.stdout)
                if len(line) > 0:
                    nodata = 0
                else:
                    nodata = nodata + 1
                    continue
                if dump_lines == True:
                    print( line )
                    logging.debug("LINE {}: {}".format(self.hna(),line))
            elif p.poll() is not None:
                dead_already = True
                l_pids[self.tnum] = 0
                break
            else:
                nodata = nodata + 1
                time.sleep(nodata_sleep)
                continue

            if line[0:32] == 'TLS server extension "heartbeat"':
                line = self.readline_decode(p.stdout)
                if line[:9] == "0000 - 01":
                    self.ts.ext_heartbeat = True
            elif line[0:8] == "Server: " and self.ts.server_string == "":
                self.ts.server_string = line[8:].replace("$",r"").strip(strip_chars)
            elif line[0:27] == "Strict-Transport-Security: ":
                self.ts.hsts = True

        if dead_already == False:
            p.terminate()
            l_pids[self.tnum] = 0

        logging.debug("scan_second({} {}) complete: sessionid={}".format(
            self.ts.addr, self.ts.hostname, self.ts.session2))

    # scan_specific_cipher can be used to search for specific ciphers and match
    # them to a stripped line returned by openssl. 
    # Example, 
    #     cl = '-cipher ECDHE:DHE'
    #     ml = 'Server Temp Key:'
    #     match = 'Bits'
    # to match:
    # Server Temp Key: ECDH, P-256, 256 bits
    def scan_specific_cipher(self, cl, match=None, ml='Cipher'):
        logging.debug("scan_specific_cipher starting({}): {}".format( match, self.hna() ))
        logging.debug("  match_line='{}'   match='{}'".format(ml, match))
        cmdlist = self.build_cmdlist( cl.split(' ') )
        found_match = False
        rf = None # return found line

        if dump_lines:
            print('-- SCAN SPECIFIC ---')
            print('-- {}'.format(cmdlist))
            print('--')

        logging.debug("- executing {}".format( cmdlist ))
        p = subprocess.Popen(
            cmdlist,
            env=g_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        l_pids[self.tnum]  = p.pid
        l_addrs[self.tnum] = self.ts.addr
        l_times[self.tnum] = int(time.time())

        request = getcmd.format(self.hna()).encode()
        if dump_lines:
            print( "\n{}\n".format( request ))
            logging.debug( request )
        p.stdin.write( request )
        line = self.readline_decode(p.stdout)
        p.stdin.close()

        dead_already = False
        nodata = 0
        poll_obj = select.poll()
        poll_obj.register(p.stdout, select.POLLIN)

        while nodata < nodata_max and not found_match:
            line = ""
            if poll_obj.poll(0):
                line = self.readline_decode(p.stdout)
                if len(line) > 0:
                    nodata = 0
                else:
                    nodata = nodata + 1
                    continue
                if dump_lines == True:
                    print( line )
                    logging.debug("LINE {}: {}".format(self.hna(),line))
            elif p.poll() is not None:
                dead_already = True
                l_pids[self.tnum] = 0
                break
            else:
                nodata = nodata + 1
                time.sleep(nodata_sleep)
                continue
            if match:
                if line[0:16].strip().find(ml) != -1:
                    if line[16:].find(match) != -1:
                        found_match = True
                        rf = line
            else:
                # just look for normal HTTP/1.1 200 OK or similar
                if line[0:5] == "HTTP/":
                    found_match = True
                    logging.debug("Found HTTP line")

        if dead_already == False:
            p.terminate()
            l_pids[self.tnum] = 0

        logging.debug("scan_specific_cipher ({}) complete: {} match={}".format(
           match, self.ts.addr, found_match))
        return found_match, rf

    # Try to connect with ONLY PFS ciphers
    def scan_pfs(self):
        self.ts.pfs,rf = self.scan_specific_cipher('-cipher ECDH:DH', 'bits', ml='Server Temp Key:')
        if rf:
            self.ts.fs_key = rf[17:]

    def scan_ssl3(self):
        self.ts.ssl3,rf = self.scan_specific_cipher('-ssl3')

    def scan_rsa(self):
        self.ts.rsa,rf = self.scan_specific_cipher('-no_tls1_3 -cipher RSA')

    def scan(self):
        global exceptions, stay_alive, dump_ts
# TlsStats Scanning States
        FIRST = 0
        SECOND= 1
        PFS   = 3
        SSL3  = 4
        RSA   = 5
        DONE  = 7
        ERROR = 9
        RUNNING = ( FIRST, SECOND, PFS, SSL3, RSA )
        STATE_NAMES = { FIRST: "First", SECOND: "Second",
            SSL3: "SSL3", PFS: "PFS", RSA: "RSA",
            DONE: "DONE", ERROR: "Error" }

        state = FIRST
        max_tries = 100

        try:
            while max_tries > 0 and state in RUNNING:
                last = state
                max_tries = max_tries - 1
                logging.debug( "{:25} State = {}".format( self.ts.hna(), STATE_NAMES[ state ]))
                if state == FIRST:
                    state = ERROR
                    self.scan_first()
                    if self.ts.success == True:
                        state = SECOND
                elif state == SECOND:
                    state = ERROR
                    self.scan_second()
                    if self.ts.success == True:
                        if self.ts.need_pfs_check == True:
                            self.ts.rsa = True
                            state = PFS
                        elif self.ts.need_ssl3_check == True:
                            state = SSL3
                        else:
                            state = RSA
                # IO Exceptions for specific ciphers just mean no cipher support
                elif state == PFS:
                    state = ERROR
                    try:
                        self.scan_pfs()
                    except IOError as ioe:
                        logging.debug("{:15} - IO Exception, state = {} (OKAY)".format(self.ts.hna(), STATE_NAMES[last]))
                    # if PFS fails, but we need to do SSL3
                    if self.ts.need_ssl3_check == True:
                        state = SSL3
                    elif self.ts.success == True:
                        state = DONE
                elif state == SSL3:
                    state = ERROR
                    try:
                        self.scan_ssl3()
                    except IOError as ioe:
                        logging.debug("{:15} - IO Exception, state = {} (OKAY)".format(self.ts.hna(), STATE_NAMES[last]))
                    if not self.ts.rsa:
                        state = RSA
                elif state == RSA:
                    try:
                        self.scan_rsa()
                    except IOError as ioe:
                        logging.debug("{:15} - IO Exception, state = {} (OKAY)".format(self.ts.hna(), STATE_NAMES[last]))
                    if self.ts.success == True:
                        state = DONE

        except IOError as ioe:
            exceptions = exceptions + 1
            logging.warning("{:15} - IO Exception, state = {}".format(
                        self.ts.hna(), STATE_NAMES[last]))
            # IOError should just drop out of the scan
        except Exception as e:
            exceptions = exceptions + 1
            # Any other exception should kill the program biotches
            logging.error("{:15} - Exception {} Arguments {}".format(self.ts.hna(), type(e), e.args))
            print( "{:20} - Exception {} Arguments {}".format(self.ts.hna(), type(e), e.args) )
            traceback.print_exc()
            stay_alive = False

        if self.ts.success == True and dump_ts == True:
            print( "Server     : {}".format(self.ts.server_string) )
            print( "Subject    : %s" % self.ts.subject )
            print( "Issuer     : %s" % self.ts.issuer )
            print( "Protocol   : %s" % self.ts.protocol )
            print( "Cipher     : %s" % self.ts.cipher )
            print( "RSA        : {}".format( self.ts.rsa ))
            print( "SSLv3      : {}".format( self.ts.ssl3 ))
            print( "Key Size   : %d" % self.ts.pksize )
            print( "Temp Key   : {}".format ( self.ts.fs_key ) )
            print( "Tickets    : " + str(self.ts.ext_tickets) )
            print( "Secure R   : " + str(self.ts.ext_secure_reneg) )
            print( "Timeout    : %d" % self.ts.timeout )
            print( "Session1   : %s" % self.ts.session1 )
            print( "Session2   : " + self.ts.session2 )
            print( "HSTS       : {}".format(self.ts.hsts) )

            if (self.ts.is_bigip):
                print
                print( "Is BIG-IP  : YES" )
            else:
                print( "Is BIG-IP  : NO" )

    def test(self,addr,port=443):
        global g_port
        '''
            Scan a single host
        '''
        hostname = ""
        g_port = port
        if not isipaddr(addr):
            hh = socket.gethostbyname_ex(addr)
            if hh is not None:
                hostname = addr
                addr = hh[2][0]
        print( "Testing {} {}.".format(addr,hostname) )
        self.ts = TlsStats((addr,hostname))
        self.scan()
        return self.ts.success
            
    def run(self):
        global stay_alive
        while stay_alive == True:
            l_active[self.tnum] = True
            l_times[self.tnum] = int(time.time())
            self.ts = TlsStats(self.iqueue.get())
            time.sleep(sleep_time)

            self.scan()

            if oqueue != None:
                ts1 = self.ts
                oqueue.put(ts1)
            self.iqueue.task_done()
#        print "Thread {} terminating".format(self.tnum)
        l_active[self.tnum] = False

class DbUpdateThread(threading.Thread):

    def __init__(self,oqueue,cursor):
        threading.Thread.__init__(self)
        self.oqueue = oqueue
        self.cursor = cursor

    def run(self):
        global fout, db_dirty_cnt, updated, thishost, no_db_write
        global conn, foundcount, tname, marker, stay_alive

        while stay_alive:
            ts = self.oqueue.get()
            if ts.success == False:
                u = unt.format(tname, thishost, ts.addr)
            else:
                foundcount = foundcount + 1
                u = ts.build_update(tname, thishost)
            if dump_commit:
                fout.write(u + "\n")
            if (no_db_write == False):
                try:
                    self.cursor.execute(u)
                except Exception as e:
                    stay_alive = False
                    logging.error("{:15} - Exception {} Arguments {}".format(
                                ts.addr, type(e), e.args))
                    logging.error(u)
                    raise

            db_dirty_cnt = db_dirty_cnt + 1
            updated = updated + 1
            if db_dirty_cnt > dirty_commit:
                dbstatus = "Committing %d updates: %d total" % (db_dirty_cnt, updated)
                if dump_commit:
                    fout.write(dbstatus + "\n")
                db_dirty_cnt = 0
                if (no_db_write == False):
                    conn.commit()
            self.oqueue.task_done()

def check_openssl():
        global tlsargs
        logging.debug("checking for openssl version")
        cmd = [ 'openssl', 'version' ]
        if os.path.isfile( './openssl' ):
            cmd = [ './openssl', 'version' ]
            tlsargs[0] = './openssl'
            g_env['LD_LIBRARY_PATH'] = os.getcwd()
        logging.debug("- executing {}".format( cmd ))
        o = subprocess.check_output( cmd, env=g_env )
        if o is None:
            logging.error( "Cannot execute openssl version" )
            # Might need exception handling here
            sys.exit(1)

        if MIN_OPENSSL_VERSION not in str(o):
            logging.error( "Minimum version of openssl not found.")
            logging.error( "Want : {}".format( MIN_OPENSSL_VERSION ))
            logging.error( "Found: {}".format( o.rstrip() ))
            w = subprocess.check_output( ['which', 'openssl'] )
            logging.error( "Which: {}".format( w ))
            print( "See sslscan.py usage (-h) for more information" )
            sys.exit(1)

def usage():
    print()
    print( "Usage: python sslscan.py -%s [single ip]" % optstring )
    print()
    print( "   -a name      - set value of 'altered_by' (defaults to hostname)" )
    print( "   -b buckets   - Run scan across a bucket or range 0-99 (inclusive)" )
    print( "   -c           - record commits to debug file {}".format(commit_log) )
    print( "   -d           - dump TLS records as seen" )
    print( "   -D           - dump openssl output" )
    print( "   -l lvl       - set loglevel (DEBUG, INFO, etc)" )
    print( "   -n count     - LIMIT only <count> nodes (default %d)" % max_scans )
    print( "   -p port      - Use port whatever instead of 443" )
    print( "   -P           - Enable tls_probe subproject" )
    print( "   -t threads   - set the maximum number of threads" )
    print( "   -T tbl name  - specify MYSQL table name (default %s)" % tname )
    print( "   -x           - do not update the database (diagnostic mode)" )
    print( "   -X           - skip the openssl check (not recommended)" )
    print( "   -s           - add simple s_client argument (e.g. -s ssl3)" )
    print( "   -q query     - operate on records specified by this where query" )
    print( "   -Q query     - just dump (addr,update) fields for WHERE query" )
    print( "   -h or -?     - This help" )
    print()
    print( "If a single address is specified it will be scanned and dumped " )
    print( "to screen. The database will not be updated." )
    print()
    print( "sslslcan requires a minimum version of the OpenSSL binary (and associated" )
    print( "libraries). The minimum version is currently {}".format(MIN_OPENSSL_VERSION) )
    print( "If the openssl application exists in the same folder as sslscan, " )
    print( "that is the binary that will be used." )
    print()
    print( "Examples:" )
    print( "   Scan a single host (doesn't update database)" )
    print( "   % python sslscan.py -p 4433 127.0.0.1" )
    print( "" )
    print( "   Run a typical scan" )
    print( "   % python sslscan.py -t 50 -n 500k" )
    print( "" )
    print( "   Run a scan across a previous query" )
    print( "   % python sslscan.py -Q \"ssl_there=0 and altered_by='zoola'\"" )
    print( "" )
    print( "   Run concurrent scans on two machines with different bucket values." )
    print( "" )
    print( "   Machine 1:    % python sslscan.py -t 40 -n 500k -b 1-49" )
    print( "   Machine 2:    % python sslscan.py -t 40 -n 500k -b 50-99" )
    print( "" )

def main():
    global loglvl, max_scans, thread_num, max_threads
    global conn, thishost, inquery, tname, stay_alive
    global dump_lines, dump_ts, g_port, dump_query, skip_ocheck

    # Start of Program
    skip_ocheck = False
    dump_query = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], optstring)
    except getopt.GetoptError as err:
        print( str(err) )
        usage()
        sys.exit(1)

    use_buckets = False
    bucket_start = 0 # can be single bucket or start of range
    bucket_end = 0   # if 0, then we're using single bucket

    for o,a in opts:
        if o == "-n":
            max_scans = decode_number(a)
            print( "Setting max scan to %d" % max_scans )
        elif o == "-a":
            thishost = a
        elif o == "-b":
            use_buckets = True
            n = a.find('-')
            if n == -1:
                bucket_start = decode_number(a)
            else:
                bucket_start = decode_number(a[0:n])
                bucket_end = decode_number(a[n+1:])
            if bucket_start > 99 or bucket_end > 99 or \
                bucket_end <= bucket_start:
                print( "Bucket range {}-{} invalid. Must be 0-99".format(
                        bucket_start, bucket_end) )
                sys.exit(1)
        elif o == "-c":
            dump_commit = True
        elif o in ("-h", "--help", "-?"):
            usage()
            sys.exit(0)
        elif o == "-p":
            g_port = int(a)
        elif o == "-P":
            g_probe = True
        elif o == "-d":
            dump_ts = True
        elif o == "-D":
            dump_lines = True
        elif o == "-l":
            n = getattr(logging, a.upper(), None)
            if not isinstance(n, int):
                raise ValueError('Invalid log level: %s' % a)
            loglvl = n
        elif o == "-x":
            no_db_write = True
        elif o == "-t":
            max_threads = int(a)
            print( "Setting max threads to %d" % max_threads )
        elif o == "-T":
            tname = a;
        elif o == "-q":
            inquery = a;
        elif o == "-s":
            tlsargs = tlsargs + [ "-" + a ]
        elif o == "-Q":
            inquery = a;
            dump_query = True
        elif o == "-X":
            skip_ocheck = True
        else:
            assert False, "unhandled option %s" % o

    if os.path.isfile(debug_log):
        os.remove(debug_log)

    logging.basicConfig(level=loglvl,filename=debug_log,
            format='%(asctime)s, %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s')
    logroot = logging.getLogger()
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.ERROR)
    logroot.addHandler(ch)

    if skip_ocheck:
        print( "Skipping openssl check (not recommended). Be sure you know what you are doing." )
        print( "Suggest you run make test." )
    else:
        check_openssl()

    if len(args):
        one_addr = args[0]
        max_threads = 1
        lookup = False
        '''
        for i in range(len(one_addr)):
            if one_addr[i] not in ".0123456789":
                lookup = True
        if lookup:
            # look up the address of that host
            ne = socket.gethostbyname_ex(one_addr)
            one_addr = ne[2][0]
        '''

        print( "Scanning single address " + str(one_addr) )
        dump_ts = True
        t = TlsScanThread() # iqueue,oqueue)
        rc = t.test(one_addr,g_port)
        sys.exit(not rc)

    if (max_scans < max_threads):
        max_threads = max_scans

    if len(thishost) == 0:
        thishost = socket.gethostname()

    try:
        print( "Starting SSL Scan: %d Max Threads" % max_threads )
        if os.path.isfile(marker):
            os.remove(marker);
        conn = dbparam.connect()
        logging.debug("Connected to Database.")
    except:
        print( "Error: {}".format(sys.exc_info()[0]) )
        logging.error( "Cannot connect to database server - error: {}".format(sys.exc_info()[0]))
        sys.exit(1)

    # get the list of addresses that don't have a SSL value
    cursor = conn.cursor()
    if len(inquery) == 0:
        inquery = "tcp_there = TRUE AND ssl_there IS NULL"

    if use_buckets:
        if (bucket_end == 0):
            inquery = inquery + " AND bucket = {}".format(bucket_start)
        else:
            inquery = inquery + \
                " AND bucket BETWEEN {} AND {}".format(bucket_start, bucket_end)
        
    selection = "addr,hostname"
    q = "SELECT {} FROM {} WHERE {}".format(selection, tname, inquery)
    if (max_scans != 0):
        q = q + " LIMIT {}".format(max_scans)

    logging.debug("main query: {}".format(q))

    print( "Fetching rows from database: {}".format(tname) )
    cursor.execute(q)
    dbrows = cursor.fetchall()
    cursor.close()
    print( " - Retreived {} rows.".format( len(dbrows ) ) )

    print( "Converting to static rows" )
    rows = []
    for row in dbrows:
        if dump_query == True:
            print( "{} {}".format(row[0], row[1]) )
        else:
            rows.append((row[0],row[1]))

    if dump_query == True:
        sys.exit(0)
    else:
        dbrows = [] # free this memory

    print( "Shuffling static rows" )
    logging.debug( "Shuffling Rows" )
    random.shuffle(rows)

    for row in rows:
        iqueue.put(row)

    print( "%d Records to process" % iqueue.unfinished_tasks )
    # Pick up any of the completed SSL updates and put them
    # in the database
    fout = open(commit_log, "w")

    if (iqueue.unfinished_tasks < max_threads):
        max_threads = iqueue.unfinished_tasks

    for x in range(max_threads):
        l_pids[x] = 0
        t = TlsScanThread(iqueue,oqueue)
        t.setDaemon(True)
        t.start()
        thread_num = thread_num + 1

    cursor = conn.cursor()
    t = DbUpdateThread(oqueue,cursor)
    t.setDaemon(True)
    t.start()

    qlen0 = iqueue.unfinished_tasks
    start_time = int(time.time())

    print( "Starting..." )
    while ((qlen0 - iqueue.unfinished_tasks) < max_scans) and stay_alive:
        if os.path.isfile(marker):
            break;
        time.sleep(3)
        if (iqueue.unfinished_tasks == 0):
            break;
        ustring = "Threads: |"
        t = int(time.time())
        for i in range(max_threads):
            if l_active[i] == True:
                ustring = ustring + "A"
                l_active[i] = False
            elif ((t - l_times[i]) > process_timeout) and (l_pids[i] != 0):
                try:
                    os.kill(l_pids[i], signal.SIGTERM)
                    logging.debug("Killed pid {}".format(l_pids[i]))
                except:
                    exx = "couldn't kill pid %d - %s" % (l_pids[i], 
                        sys.exc_info()[0])
                    logging.error(exx)
                    print( exx )
                ustring = ustring + "K"
            else:
                ustring = ustring + "_"
        if updated > 0:
            rate = updated / (t - start_time)
            tleft = iqueue.unfinished_tasks / max(rate,1)
            d = datetime.datetime(1,1,1) + datetime.timedelta(seconds=tleft)
            tn = "{}:{:02}:{:02}:{:02}".format(d.day-1, d.hour, d.minute, d.second)
            print( "SSLSCAN {}: q={:>5,} f={:.2%} r={:2d}/s {}| e={}".format(tn,
                iqueue.unfinished_tasks, float(foundcount)/max(updated,1),
                int(updated/(t - start_time)), ustring, exceptions))

    if os.path.isfile(marker):
        stay_alive = False
        print( "File stopper detected, ending." )
        conn.commit()

    if stay_alive == False:
        # Sometimes connections will be stuck for a long time.
        # Print out the ones that have been stuck for more than 60 seconds
        t = int(time.time())
        for j in range( min(max_threads, len(l_addrs))):
            if ((t - l_times[j]) > process_timeout):
                print( "{} outstanding for {} seconds".format(l_addrs[j],t - l_times[j]) )
        nactive = 1
        countdown = 10
        while nactive > 0 and countdown > 0:
            countdown = countdown - 1
            time.sleep(3)
            nactive = 0
            for i in range(max_threads):
                if (l_active[i] == True):
                    nactive = nactive + 1
            print( "   ...Waiting for {} threads to end.".format(nactive) )

    print( "Committing Changes..." )
    conn.commit()
    conn.close()
    fout.close()
    print( "Complete - {} Records Updated".format(updated) )

    time.sleep(3)
    sys.exit(stay_alive == True)

if __name__ == "__main__":
    main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
