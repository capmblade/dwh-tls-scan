#!/usr/bin/python
#
# 2nd-generation report
#
import sys
import os
import datetime
import dbparam
import getopt

gtn = dbparam.mkname()
nssl = 0   # number of SSL hosts
tcx = 5    # top X ciphers
tcc = 5    # top C curves
gw = ""    # Global Where
mysql = False
postgres = True
verbose = False
terse = False

class Population:
    def __init__(self, popname, clause=''):
        self.pname = popname;
        self.clause = clause;
        self.nssl   = -1
        self.data   = dict()
        self.data['tlsv13'] = 0
        self.data['tlsv12'] = 0
        self.data['tlsv11'] = 0
        self.data['tlsv10'] = 0
        self.data['ssl3']   = 0
        self.data['ssl3sup']= 0
        self.data['pfs']    = 0
        self.data['rsa']    = 0
        self.data['k256' ]  = 0 #  this is likely ECDSA?
        self.data['k512']   = 0
        self.data['k1024']  = 0
        self.data['k2048']  = 0
        self.data['k4096']  = 0
        self.data['ext_r']  = 0
        self.data['ext_t']  = 0
        self.ciphers = None
        self.curves = None

class Report:
    def __init__(self, cursor, table_name, gw0, ofn=""):
        self.c = cursor
        self.tn = table_name
        self.gw = gw0
        if len(ofn):
            if os.path.isfile( ofn ):
                bkup = "{}.bak".format(ofn)
                if os.path.isfile( bkup ):
                    print("Deleting backup file: {}".format(bkup))
                print("Renaming existing to {}".format(bkup))
                os.rename( ofn, bkup)
            self.of = open(ofn, "w")
        else:
            self.of = None

    def o(self, s):
        print(s)
        if self.of:
            self.of.write( s + "\n" )

    def b(self, s):
        self.o("\n" + s)
        self.o("-" * 55)

    def set_clause(self, c):
        self.gw = c;    

# count where
    def cw(self, s):
        c = "SELECT COUNT(1) from " + self.tn + " WHERE " + s
        if len(self.gw):
            c = c + " AND " + self.gw
        self.c.execute(c)
        row = self.c.fetchone()
        return row[0]

    def scw(self, s):
        c = "SELECT COUNT(1) from " + self.tn + " WHERE ssl_there AND " + s
        if len(self.gw):
            c = c + " AND " + self.gw
        self.c.execute(c)
        row = self.c.fetchone()
        return row[0]

# count where and output
    def cwo(self, where, label ):
        n = self.cw(where)
        self.o( "{:<40}: {:>10}".format( label, n) )
        return n

    def cwop(self, where, label, divisor):
        c = "SELECT COUNT(1) from " + self.tn + " WHERE " + where
        if len(self.gw):
            c = c + " AND " + self.gw
        self.c.execute(c)
        row = self.c.fetchone()
        self.o( "{:<40}: {:>10} ({:.2%})".format( label,
            row[0],(float(row[0])/divisor)))
        return row[0]

    # SSL - count where output and percentage!
    def scwop(self, where, label, divisor):
        c = "SELECT COUNT(1) from " + self.tn + " WHERE ssl_there AND " + where
        if len(self.gw):
            c = c + " AND " + self.gw
        self.c.execute(c)
        row = self.c.fetchone()
        if (divisor == 0):
            self.o( "{:<40}: {:>10} ({:.2%})".format( label, row[0],0))
        else:
            self.o( "{:<40}: {:>10} ({:.2%})".format( label,
                row[0],(float(row[0])/divisor)))
        return row[0]

        # DON'T CHECK THIS IN THE WAY IT IS
        # Fix it like so 
        # count = SELECT COUNT(1) FROM xxx WHERE ssl_issuer ILIKE '%GLOBALSIGN%'
        # that way it catches all the different CA's

    def cacount(self):
        c = "SELECT ssl_issuer_oname,COUNT(*) FROM " + self.tn + " WHERE ssl_there AND NOT ssl_self_signed "
        if len(self.gw):
            c = c + " AND " + self.gw
        c = c + " GROUP BY 1 ORDER BY 2 DESC"
        self.c.execute(c)
        rows = self.c.fetchall()
        count = 0
        for i in range(min(10, len(rows))):
            self.o("{:10} {:10,} {}".format( i + 1, rows[i][1], rows[i][0] ))

    def pop_banner(self, poplist, banner="Population Data"):
        pl = "\n{:13}: ".format(banner)
        for p in poplist:
            pl += "{:>10} ".format(p.pname)
        self.o(pl)

    # Print out a row of population data
    def pop_out(self, poplist, label, idx, raw=0):
        pl = "{:<13}: ".format(label)
        for p in poplist:
            if p.nssl == 0:
                pl += "{:>10} ".format("n/a")
            elif (p.data[idx] == 0):
                pl += "{:10} ".format("")
            elif raw == 1:
                pl += "{:10} ".format( p.data[idx] )
            else:
                pl += "{:10.1%} ".format( float(p.data[idx]) / p.nssl )
        self.o(pl)

    def ciphers(self, tcx, nssl):
        # Pick up top ciphers
        q = "SELECT ssl_cipher,COUNT(*) from " + gtn + \
            " WHERE ssl_there "
        if len(self.gw):
            q = q + " AND " + self.gw
        q = q + " GROUP BY ssl_cipher"
        self.c.execute(q)
        rows = self.c.fetchall()
        rows = sorted(rows, key=lambda x: x[1],reverse=True)
        count = 0
        lx = list()
        for row in rows:
            count = count + 1
            lx.append((row[0], int( (row[1]*100) / nssl )))
# to get count, include row[1] and float(row[1]/self.nssl)
            if (count > tcx):
                break;
        return lx

    def curves(self, tcc, nssl):
        q = "SELECT ssl_temp_key,COUNT(*) FROM " + gtn + \
                " WHERE ssl_pfs "
        if len(self.gw):
            q = q + " AND " + self.gw
        q = q + " GROUP BY ssl_temp_key ORDER BY 2 DESC"
        self.c.execute(q)
        rows = self.c.fetchall()
        count = 0
        lx = list()
        for row in rows:
            count = count + 1
            if (count > tcc) or not row[0]:
                break;
            lx.append((row[0], int( (row[1]*100) / nssl )))
        return lx

    def footer(self):
        self.b( "Report Notes" )
        self.o( "* Blanks: If a column is blank, then its value is literally 0. ")
        self.o( "* 0.0%:   If a column is 0.0% but not blank, then it is < 0.1% ")
        self.o( "* >:      > Signifies neither F5 nor a CDN" )

# =========================================================================

optstring = "g:T:hmo:pv0?"

def usage():
    print()
    print("Usage: python report.py -%s" % optstring)
    print()
    print("   -T tblname   - update table <tblname>")
    print("   -m or -p     - mysql or postgres (default)")
    print("   -g query     - operate on records specified by this where query")
    print("   -v           - verbose - add a few extra queries")
    print("   -o file      - also output to file.")
    print("   -h or -?     - This help")
    print("   -0           - a few header stats to check progress of on-going scan")
    print()
    print("Example:")
    print("   % python report.py -g 'ssl_issuer LIKE '%verisign%'")
    print("")

def main():
    global gw,gtn,mysql,postgres,verbose,terse
    ofn = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], optstring)
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(1)

    for o,a in opts:
        if o == "-T":
            gtn = a
        elif o == "-m":
            mysql = True
            postgres = False
        elif o == "-o":
            ofn = a
        elif o == "-p":
            mysql = False
            postgres = True
        elif o == "-g":
            if a[0:5] == "WHERE":
                gw = a[6:]
            else:
                gw = a
        elif o == "-v":
            verbose = True
        elif o == "-0":
            terse = True
        elif o == "-?" or o == "-h":
            usage();
            sys.exit(1)

    try:
        conn = dbparam.connect(mysql)
    except:
        sys.stderr.write( "Error: {}\n".format( sys.exc_info[0] ) )
        logging.error( "Cannot connect to server - error: {}".format(sys.exc_info[0]))
        sys.exit(1)

    r = Report(conn.cursor(), gtn, gw, ofn)

    if terse:
        banner = "dwh-tls-scan database terse stats: "
    else:
        banner = "Report: ";
    banner = banner + datetime.datetime.now().strftime("%Y-%m-%d")
    if (gtn != "t1"):
        banner = banner + ": TABLE = '" + gtn + "'"
    r.b( banner )
    if len(gw) > 0:
        r.b("   GLOBAL WHERE CLAUSE = '{}'".format(gw))

    r.b( "Summary Statistics" )
    # Number of records in the database
    
    c = "SELECT COUNT(*) from " + gtn
    if len(gw):
        c = c + " WHERE " + gw
    cursor = conn.cursor()
    cursor.execute(c)
    row = cursor.fetchone()

    if verbose or terse:
        r.o( "{:<40}: {:>10}".format( "Tables Entries", row[0]))
        r.cwo( "tcp_there IS NULL", "Unprocessed Entries" )
        r.cwo( "tcp_there AND ssl_there IS NULL", "Unprocessed TCP Hosts" )

    # Number of TCP Hosts
    r.cwo( "tcp_there", "TCP Hosts" )

    # Number of SSL Hosts
    nssl = r.cwo( "ssl_there", "SSL Hosts" )

    if terse:
        sys.exit(0)
    
    # Number of Self-Signed Hosts
    r.scwop( "ssl_self_signed", "Self-Signed Hosts", nssl)

    # Number of Hosts offering Strict Transport Security
    r.scwop( "ssl_hsts", "Strict Transport Security (STS)", nssl)

    # Number of Hosts offering Strict Transport Security
#    r.scwop( "ssl_hsts AND ssl_is_bigip",
#            "STS (F5 only)", nssl)

    # Number of F5 Hosts
    nbigip = r.scwop( "ssl_is_bigip", "F5 Hosts", nssl )

    # Number of Akamai Hosts
    nakamai = r.scwop( "ssl_is_akamai", "Akamai Hosts", nssl )

    # Number of Cloudflare Hosts
    ncloudflare = r.scwop( "ssl_is_cloudflare", "Cloudflare Hosts", nssl )

    # Forward Secrecy (any DHE cipher)
    #r.scwop( "ssl_cipher LIKE '%DHE%' OR ssl_protocol LIKE 'TLSv1.3'", "Forward Secrecy", nssl)
    r.scwop( "ssl_pfs", "Forward Secrecy", nssl)

# Here we go with Populations
    pops = list()
    pops.append( Population('All') )
    pops.append( Population('F5', 'ssl_is_bigip') )

    if nakamai > 0:
        pops.append( Population('Akamai', 'ssl_is_akamai') )

    if ncloudflare > 0:
        pops.append( Population('Cloudflare', 'ssl_is_cloudflare') )

    pops.append( Population('Others',  "ssl_is_bigip = False AND ssl_is_akamai = False AND ssl_is_cloudflare = False") )
    pops.append( Population('>Apache', "ssl_is_bigip = False AND ssl_server_string LIKE 'Apache%'") )
    pops.append( Population('>NGINX',  "ssl_is_bigip = False AND ssl_server_string LIKE 'nginx%'") )
    pops.append( Population('>IIS',    "ssl_is_bigip = False AND ssl_server_string LIKE 'Microsoft-IIS%'") )

    for p in pops:
        r.set_clause(p.clause)
        p.nssl = r.cw( "ssl_there")
        p.data['nssl']       = p.nssl
        if (p.nssl > 0):
            p.data['tlsv13'] = r.scw("ssl_protocol = 'TLSv1.3'")
            p.data['tlsv12'] = r.scw("ssl_protocol = 'TLSv1.2'")
            p.data['tlsv11'] = r.scw("ssl_protocol = 'TLSv1.1'")
            p.data['tlsv10'] = r.scw("ssl_protocol = 'TLSv1'")
            p.data['ssl3']   = r.scw("ssl_protocol = 'SSLv3'")
            p.data['ssl3sup']= r.scw("ssl_v3")
            p.data['ext_r']  = r.scw("ssl_ext_reneg_sec")
            p.data['ext_t']  = r.scw("ssl_ext_tickets")
            p.data['k256']   = r.scw("ssl_pksize = 256 AND ssl_cipher LIKE 'ECDHE-ECDSA%'")
            p.data['k512']   = r.scw("ssl_pksize = 512")
            p.data['k1024']  = r.scw("ssl_pksize = 1024")
            p.data['k2048']  = r.scw("ssl_pksize = 2048")
            p.data['k4096']  = r.scw("ssl_pksize = 4096")
            p.data['pfs']    = r.scw("ssl_pfs")
            p.data['rsa']    = r.scw("ssl_rsa")
            p.data['hsts']   = r.scw("ssl_hsts")

            p.ciphers = r.ciphers(tcx, p.nssl)
            p.curves = r.curves(tcx, p.nssl)

    r.b( "Populations" )
    r.pop_banner(pops, "Metrics")
    r.pop_out(pops, "SSL Hosts",     'nssl', 1)

    r.pop_banner(pops, "Preferred")
    r.pop_out(pops, "TLSv1.3",       'tlsv13')
    r.pop_out(pops, "TLSv1.2",       'tlsv12')
    r.pop_out(pops, "TLSv1.1",       'tlsv11')
    r.pop_out(pops, "TLSv1.0",       'tlsv10')
    r.pop_out(pops, "SSLv3",         'ssl3')

    r.pop_banner(pops, "Extras")
    r.pop_out(pops, "PFS",           'pfs')
    r.pop_out(pops, "HTTP STS",      'hsts')
    r.pop_out(pops, "RSA",           'rsa')

    r.pop_banner(pops, "Supported")
    r.pop_out(pops, "v3 Support",    'ssl3sup')
    r.pop_out(pops, "Secure Reneg",  'ext_r')
    r.pop_out(pops, "Session Tix",   'ext_t')

    r.pop_banner(pops, "Key Sizes")
    r.pop_out(pops, "256 ECDSA",     'k256')
    r.pop_out(pops, "Key 512",       'k512')
    r.pop_out(pops, "Key 1024",      'k1024')
    r.pop_out(pops, "Key 2048",      'k2048')
    r.pop_out(pops, "Key 4096",      'k4096')

    r.b( "Top Preferred Ciphers" )
    for p in pops:
        r.o( "\n{}".format(p.pname) )
        if p.ciphers is not None:
            for i in range(min(tcx, len(p.ciphers))):
                r.o( "{:>5}: {:30} {:3}%".format(i+1, p.ciphers[i][0], p.ciphers[i][1]) )
#print "{:>5}: {:40} {:>3}%".format(i+1, p.ciphers[i][0], p.ciphers[i][1])
#        for i in range(min( tcx, len(p.ciphers) ) ):

    r.b( "Elliptic Curves in Use" )
    for p in pops:
        r.o( "\n{}".format(p.pname) )
        if p.curves is not None:
            for i in range(min(tcc, len(p.curves))):
                r.o( "{:>5}: {:30} {:3}%".format(i+1, p.curves[i][0], p.curves[i][1]) )

#    SELECT ssl_issuer,COUNT(*) FROM p_2018q1 WHERE ssl_there AND NOT ssl_self_signed GROUP BY ssl_issuer ORDER BY 2 DESC;
    r.set_clause("")
    r.b( "Certificate Authority Counts" )
    r.cacount()

    r.footer()

if __name__ == "__main__":
    main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
