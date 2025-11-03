#!/usr/bin/python3

import json
import platform
import subprocess
import datetime
 

data = {
	"Listeners": [],
	"Fwrules": [],
	"Interfaces": [],
	"Routes": [],
	"Hostname": "",
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
	data["Hostname"] = platform.node()
	data["Interfaces"] = runp(["ifconfig"])
	data["Listeners"] = runp(["sudo", "netstat", "-tulpn"])
	data["Routes"] = runp(["netstat", "-rn"])
	data["Ufwrules"] = runp(["sudo", "ufw", "status"])

	now = datetime.datetime.now()
	data["Date"] = now.strftime("%Y-%m-%d %H:%M:%S")


	f = open("nchecknetraw-server.json", "w")
	f.write(json.dumps(data))
	f.close()

	#curl -k --data-binary "@nchecknetraw-server.json" -X POST https://wanted.lewi.nl/api/procraw"

main()
