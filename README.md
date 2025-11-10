# nchecknet
Nchecknet compares ufw against netstat -ntlp, netstat -rn, ifconfig and nmap

Usage:

Run execute/webserver.

Use utils for:

*  -NchecknetUrl string
    	--> NchecknetServer URL (default "https://nchecknet.lewi.nl")
*  -cn string
    	--> Create collector script for Nmap-site
*  -cs string
    	--> Create collector script for FQDN (server)
*  -ns string
    	--> New Server

Copy the server-collector script to the server that must be checked.
Run the script once per day. (or more frequent, the last run wil overwrite prevous runs of this day.)

Copy the nmap-collector-scripts to locations behind the interfaces, e.g. eth0 is often linked to 0.0.0.0, so the eth0 script shoukld be run from somewheren at the internet.
Run the script once per day. (or more frequent, the last run wil update prevous runs of this day.)

To view the network-connections of the server: https://NCHECKNETSERVER/nmap_suggestions

To see a rudimentory report: ./execute/collectfwdata







