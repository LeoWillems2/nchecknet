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


def scan(scanname):
	global data

	data["Nmap"] = runp(["nmap", scanname ])
	data["Hostname"] = platform.node()
	data["Scanname"] = scanname
	now = datetime.datetime.now()
	data["Date"] = now.strftime("%Y-%m-%d %H:%M:%S")

	f = open("/tmp/nchecknetraw-nmap.json", "w")
	f.write(json.dumps(data))
	f.close()

	runp(["curl","-k","--data-binary","@/tmp/nchecknetraw-nmap.json","-X","POST","https://nchecknet.lewi.nl/api_nmap"])

def main():
	scannames = SCANNAMES
	for s in scannames:
		scan(s)

main()
