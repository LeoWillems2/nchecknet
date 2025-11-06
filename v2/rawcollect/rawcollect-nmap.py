#!/usr/bin/python3

import json
import platform
import subprocess
import datetime
 

data = {
	"Nmap": [],
	"Hostname": "",
	"Scanname": "",
	"Date": "",
	"Key": "ABCDEF0123456789"
}

def runp(command):
	result = subprocess.run(
		command,
		capture_output=True,
		text=True,
		check=True
	)
	lines = result.stdout.strip().split("\n")
	return lines



def main():

	runp(["curl","-k","--data-binary","@nchecknetraw-nmap.json","-X","POST","http://127.0.0.1:8080/api_nmap"])
	return

	## hostname -s arg1  -k arg2
	scanname = "monitor.managedlinux.nl"

	data["Nmap"] = runp(["nmap", scanname ])

	data["Hostname"] = platform.node()
	data["Scanname"] = scanname
	now = datetime.datetime.now()
	data["Date"] = now.strftime("%Y-%m-%d %H:%M:%S")

	f = open("nchecknetraw-nmap.json", "w")
	f.write(json.dumps(data))
	f.close()

	runp(["curl","-k","--data-binary","@nchecknetraw-nmap.json","-X","POST","http://127.0.0.1:8080/api_nmap"])

main()
