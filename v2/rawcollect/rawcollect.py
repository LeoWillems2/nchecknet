#!/usr/bin/python3

import json
import platform
import subprocess
 

data = {
	"listeners": [],
	"ufwrules": [],
	"interfaces": [],
	"hostname": "",
	"key": "ABCDEF0123456789"
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
	data["hostname"] = platform.node()
	data["interfaces"] = runp(["ifconfig"])
	data["listerners"] = runp(["ss", "-nltup"])
	data["ufwrules"] = runp(["sudo", "ufw", "status"])

	f = open("ncheckraw.json", "w")
	f.write(json.dumps(data))
	f.close()

	#curl -k --data-binary "@nchecknetraw.josn" -X POST https://wanted.lewi.nl/api/procraw"
