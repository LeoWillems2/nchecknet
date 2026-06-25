# nchecknet
Nchecknet compares nftables  against netstat -ntlp, netstat -rn, ifconfig and nmap

![](v2/docs/nchecknet1.png)
![](v2/docs/view3.png)
![](v2/docs/view2.png)
![](v2/docs/view1.png)


Required: mongodb, golang

Build: cd v2; go mod tidy; make

Usage:

* Run ./bin/webserver for view and edit reports and to generate nmap-scripts for the remote locations.
* Run ./bin/collector to receive data.

Use ./bin/utils for:
```
  -O string
    	Owner
  -P string
    	Password
  -R string
    	Rights
  -cl string
    	Collector url
  -i string
    	Ident
  -cs string
    	Create collector script for FQDN (server)
  -i2 string
    	Compare 2 Sessions: -i s1 -i2 s2 -s fqdn
  -if string
    	Interface
  -nm
    	Create nmapcollector script for FQDN (server), use: -i ident  -if iface -s server -cl nchecknetserver
  -ns string
    	New Server, add: -O
  -nu string
    	New User: -nu username -P password -O owner -R [awr]
  -pp string
    	PrettyPrint [Struct:HN:SID]
  -r	Report
  -s string
    	Server FQDN
  -sb string
    	Set baseline: -sb hostname -i sessionid
```

* Rights:

|symbol|description|
|--|--|
|a|admin, see all systems|
|w|edit comments and hide systems|
|r|read-only|
  

Copy the server-collector script to the server that must be checked.
Run the script (as root) once per day. (or more frequent, the last run wil overwrite prevous runs of this day.)

Generate the nmap-collector scripts from the Systems-tab of the webserver.
Copy the nmap-collector-scripts to locations behind the interfaces, e.g. eth0 is often linked to 0.0.0.0, so the eth0 script shoukld be run from somewheren at the internet.
Run the script (as root) once per day. (or more frequent, the last run wil update prevous runs of this day.)

* nchecknet.yml in etc:

```
 webserver:
   jwtsecret: "a long secret"
   port: 8086
   mongodburl: "mongodb://....."
   maxsessionidselect: 3
   webroot: [path to webroot]

 collector:
   collectorurl: "https://FQDN"
   port: 8087
```

== Quick start ==

Setup a user and a server to monitor:
```
bin/utils -nu john -O JohnOrg -P johnpass -R a
bin/utils -ns server.john.org -O JohnOrg

```
Start the collector and webserver.
Setup the collector and nmap scripts:
```
bin/utils -cs server.john.org >collector-script
chmod 755 collector-script &&  scp collector-script server.john.org: && ssh server.john.org sudo ./collector-script
bin/utils -nm -i 20260612 -if eth0 -s server.john.org >nmap-script   ## replace 20260612 by todays date.
chmod 755 nmap-script &&  scp nmap-script somewhere: && ssh somewhere sudo ./nmap-script
```
Move nmap-script and collector-script to /etc/cron.daily


