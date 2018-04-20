# dwh-tls-scan

## TLS Scanning Tool

## Overview

dwh-tls-scan is a research tool that I've built and run for the last
four years. Its a multi-threaded python scanner built on top of openssl.
It basically scrapes the output of the openssl s_client tool to fetch
cipher selections and then it dumps the output into a Postgres database.
Queries can be run against that database to generate reports, which
can used to track changes over time (trends).

### Steps

There are five steps to running the scanner and getting data.

1. Setup / database creation.
2. Loading database with IP addresses
3. TCP scans (to eliminate dead hosts)
4. SSL Scans
5. Reporting

### Should you use this scanner?
Probably not. :) This project was a personal research project 
in 2014, but in the intervening years, other projects have evolved 
that already have complete data (censys.io for example) or have
better-supported tools (zmap). Still, for completeness, let me
walk you through how this works.

### Two Types of Scans

The dwh-tls-scan project supports two types of scans, depending on 
the input data. Fan IPv4 mass scan, the scanner can import
a giant list of IP addresses that you can get from anywhere. I get them
from Project Sonar. 

The scanner also supports Alexa-type Top 1 Million hostnames. The ranking
isn't really important, but the scanner uses those ranks to support
distributed nodes.

## Requirements
* Python3. It used to be python2, but upgraded to support other tools. 
* PostGreSQL. No particular version, though I am on 9.5.12 because AWS.
* OpenSSL v1.1. You can't scan for TLS1.3 without that.

## Setup

The scanner assumes a PostGreSQL backend for data storage. I'm using
AWS RDS but any PostGres environment should work fine. After you set
up all your subnets, vpcs, db admins etc, you'll want to create a
database to hold your scanning data.

`psql -h <host> -U <username> -c "CREATE DATABASE scans OWNER <username>"`

Every row in your db is about 3K, so assume 1GB if you want to just
scan Alexa. If you wanted to do every host in project sonar repo,
then you need 200Gb.

Next create this INI file so that scanner code can connect to the db.
You might want to create a ~/.pgpass file (google that format) with the
same info so you don't get prompted all over the place when you run psql.

`# dwh-tls-scan.ini
[POSTGRES]
password = your-db-user-password
host = your-postgres-host
port = 5432
db_name = scans`

## Scanning

Recall that there are two types of scans support. Mass scans (lists of
IP addresses) and ranked scans (lists of hostnames).

### Mass Scanning

First you'll initialize an empty database table with the idb.py tool.
By default it will choose a name like 'i<year><quarter>', but you can
specify whatever you like.

`% python3 idb.py -I scan1``

Next, go get a giant hosts file hosts files from project sonar at this URL:
https://scans.io/study/sonar.ssl

There will be multiple file types (2018*certs.gz, 2018*hosts.gz). Be sure
you pick the 'hosts.gz' file. I dl them directly to my EC2 instance via
wget. Latest ones are pretty big, like 1.1G compressed. Unzip file.

`% gzip -d 2018*hosts.gz`

Next step is to populate the table you created with a row for each IP address.
You could just import all of the IP addresses into the table if you want, but
watch out there will be duplicates, which is not helpful in our case.  Use the
randomhosts.py tool to grab, say, 100,000 addresses randomly from the file and
import them into the database (by default does 5%).

`% python randomhosts.py -n 100k ../data/2018*hosts |
     cut -d, -f1 | sort -u |
     psql scans -c "COPY scan1` (addr) FROM stdin;"`

Ideally you'll see something like

'Line Estimate 65466818
Pulling 100000 lines from input.
COPY 100102'

Which indicates success. 

Next step: For whatever reason, between 5-15% of hosts that Project Sonar
found somehow disappear or are unreachable for me. So the tcpscan.py figures
out what's still there from a TCP perspective.

`% python3 tcpscan.py -T scan1``

You'll see the TCP scanner start chugging away on the database.

`TCPSCAN 0:04:45:31 q=99,863 o=0 f=86.19%   5/s Threads |__A_AAA_A_|
TCPSCAN 0:04:17:38 q=99,805 o=0 f=86.87%   6/s Threads |AA_A___A_A|
TCPSCAN 0:03:23:11 q=99,685 o=0 f=89.21%   8/s Threads |AAAAAAAAAA|
`
You can stop it via ^C, or create a file called 'stop' in the same
directory and that will stop the main loop and commit the changes.

Make it faster by specifying more threads with -t. On a medium instance I'm using 50-75 threads per instance.

The last step is the SSL scanning part, which is the same for both types
of scans, so jump to the section SSL Scanning below.

## Ranked Scanning

Ranked scanning is similar to mass scanning with one important exception.
It uses hostnames to connect to the TLS hosts so it can capture hosts that
require the ServerNameIndicator extension. An intermediate 'rank'
database is created, which you don't really need to know about, but the 
process is slightly different from mass scanning above.

First, go grab either the Alexa or OpenDNS top 1 million lists from:
   Alexa: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
   OpenDNS: http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip

Unzip it.

Create a new rank database and read the file into it:

`% python3 idb.py -r -l top-1m.csv scan1_r`

Run the tcpscan.py utility on the rank database.

`% python3 tcpscan.py -r -t 25 -T scan1_r`

You'll see it chugging along for a few minutes or hours. Next, create
the REAL database that we'll use for SSL scanning.

`% python3 idb.py -I scan1`

Copy the rank database (_r) into the real database.

`% psql scans
   => INSERT INTO scan1 (addr,alexa_rank,hostname,tcp_there)
            SELECT DISTINCT ON (addr) addr,rank,hostname,tcp_there
                    FROM scan1_r WHERE tcp_there;`
                    
Now we're ready to actually run an SSL scan.

## SSL/TLS Scanning

Armed with a table of IP addresses, the sslscan.py utility will connect
to each one using the openssl s_client tool and record different parameters.
It requires a minimum version of openssl v1.1. If your system doesn't have
that, go to www.openssl.org, find the github source, clone it, build it, and
copy three files into this directory:
* openssl
* libcrypto.so.1.1
* libssl.so.1.1

See CHEATSHEET.md for info on how to properly build openssl.

Don't worry, if you try running sslscan.py without that minimum version
it will complain.

Finally we're ready to go get some SSL statistics. Run the sslscan.py
tool the same way you ran the tcpscan.py tool.

`% python3 sslscan.py -T scan1`

You'll see it happily chugging along, running 25 threads at a time.
The A's stand for 'active' threads. If one gets hung, it will eventually
be killed and you'll see a 'K'. The e's stand for exceptions
which might be a network exception or what have you.

## Reporting

After your scan is complete, you've got a database table full of statistics.
You can run your own queries on it, as one might, or you can use the handy
report.py module to run some queries for you and generate a little report.

`% python3 report.py -T scan1 -o report1.txt`

If you specify -o you'll get a copy in whatever file you specify.

The report looks like this:


Report: 2018-04-20: TABLE = 'scan1'
-------------------------------------------------------

Summary Statistics
-------------------------------------------------------
TCP Hosts                               :      89532
SSL Hosts                               :      47119
Self-Signed Hosts                       :       5420 (11.50%)
Strict Transport Security (STS)         :       2118 (4.50%)
F5 Hosts                                :        195 (0.41%)
Akamai Hosts                            :      11564 (24.54%)
Cloudflare Hosts                        :        497 (1.05%)
Forward Secrecy                         :      41877 (88.87%)

And then there's a bunch of breakdowns by server type, and a 
count of certificate authorities and cipher preferences. And
curve types. The reports are what I keep around; I eventually
delete all the tables for disk space.

## Debugging

All tools can be debugged with pdb3. tcpscan.py writes to _tcpdebug.log
and sslscan.py writes to _debug.log. Both utilities can be enticed to
provide extra logging via the -l DEBUG parameter. See -h on all utilities
for complete usage.

If you need additional help, I'm only an email away at d dot holmes at
f5.com. 

Again, I make no claims that this is an awesome scanner. This is a decent
scanner, more of a personal project of interest than some kind of super
speedy, industrial, scan-the-whole internet tool. But it works for me, and
I've been happy to build it. Make of that what you will, and happy scanning!

