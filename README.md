# nchecknet
Nchecknet compares nftables  against netstat -ntlp, netstat -rn, ifconfig and nmap

![](v2/docs/nchecknet1.png)
![](v2/docs/view1.png)
![](v2/docs/view2.png)
![](v2/docs/view3.png)


Required: mongodb, golang

Build: cd v2; go mod tidy; make

Usage:

* Run ./bin/webserver for view and edit reports and to generate nmap-scripts for the remote locations.
* Run ./bin/collector to receive data.

Use ./bin/utils for:

*  -cs string
    	--> Create collector script for FQDN (server)
*  -ns string
    	--> Add a new Server -- also set -O(wner)
*  -nu string
		--> Add a new User -- also set -P(assword), -O(wner), -R(ights)
   
* Rights:

|symbol|description|
|--|--|
|a|admin, see all systems|
|w|edit comments and hide systems|
|r|read-only|
  

Copy the server-collector script to the server that must be checked.
Run the script once per day. (or more frequent, the last run wil overwrite prevous runs of this day.)

Generate the nmap-collector scripts from the Systems-tab of the webserver.
Copy the nmap-collector-scripts to locations behind the interfaces, e.g. eth0 is often linked to 0.0.0.0, so the eth0 script shoukld be run from somewheren at the internet.
Run the script once per day. (or more frequent, the last run wil update prevous runs of this day.)

* nchecknet.yml in etc:

```
 webserver:
   jwtsecret: "a long secret"
   port: 8086
   mongodburl: "mongodb://....."
   maxsessionidselect: 3

 collector:
   collectorurl: "https://FQDN"
   port: 8087
```

