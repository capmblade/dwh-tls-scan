# dwh-tls-scan CHEATSHEET

Repo for the code portion of the SSL scanner.

Files:
idb.py 		- Initialize a new blank database
randomhosts.py	- Download hosts file from project sonar, give to this guy
tcpscan.py	- Run through database checking for TCP open status
sslscan.py	- Collect SSL statistics for database
report.py  - Run a report across the database

[ For a mass scan of the internet ]
1. Pull a hosts file from Project Sonar
   https://scans.io/study/sonar.ssl
2. Unzip it
3. Create a new database, use i_yearqn like i_2017q1
   python idb.py -I i_2017q1
4. Use randomhosts.py to read into database like so
   python randomhosts.py -n 3000000 ../data/hosts |
     cut -d, -f1 | sort -u |
     psql scans -c "COPY i_2017q1 (addr) FROM stdin;"
5. Then run tcpscan.py on it.
     python tcpscan.py -t 50 -T i_2017q1
6. And then run sslscan.py on it.
     python sslscan.py -t 50 -T i_2017q1

[ For Alexa or OpenDNS ]
1. Pull the file down from internet
   Alexa: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
   OpenDNS: http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
2. Create a new 'rank' database (a small table) and read file into it
   The database will have just the rank and hostname at first.
   python idb.py -r -l ../data/top-1m.csv o_2017q1_r
3. Run tcpscan.py on it to resolve hostname and initial tcp_there
   python tcpscan.py -r -t 50 -T o_2017q1_r
4. Create a blank sslscan database.
   python idb.py -I o_2017q1
5. Copy the rank database into the new sslscan database
   psql scans
   => INSERT INTO o_2017q1 (addr,alexa_rank,hostname,tcp_there) 
	    SELECT DISTINCT ON (addr) addr,rank,hostname,tcp_there
		FROM o_2017q1_r WHERE tcp_there;
6. To add another rank table to the same database, create this rule
     CREATE RULE "my_table_on_duplicate_ignore" AS ON INSERT TO "cp_2017q2"
       WHERE EXISTS(SELECT 1 FROM cp_2017q2 WHERE (addr)=(NEW.addr))
         DO INSTEAD NOTHING;
   Then do the insert as above (step 5). Then drop the rule
     DROP RULE "my_table_on_duplicate_ignore" ON "cp_2017q2"
7. Then run sslscan.py on it

[ OpenSSL 1.1.0 support ] - Dec 3, 2017 - Seattle

Starting this month I've enabled OpenSSL 1.1.0 support,
specifically so I can get access to the 'Server Temp Key' output
line which gives us curve information.

Unfortunately, 1.1.x contains some side-effects that make life 
difficult for sslscan. First, it dumps a whole record of text
that "looks like" a correct TLS connection, but is actually empty.
To combat that, we now look for 'Cipher: 0000' as a 'bad' marker.

Also, 1.1.x disables ssl3 and rc4. We can re-enable them by building
openssl with this command line:

./Configure enable-tls1_3 enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers enable-heartbeats linux-x86_64

Copy the openssl app and libraries (libcrypto and libssl) to the
same directory as sslscan and it will use them there. Or go with
symbolic links. Or upgrade the containing OS to use 1.1.x

