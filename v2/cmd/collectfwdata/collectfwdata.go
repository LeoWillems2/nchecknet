package main

/*
	process raw UFW rules / Interfaces / Listeners for access
		- UFW: *on interface*: does not support in or out
*/

import "github.com/LeoWillems2/nchecknet/pkg/sharedlib"

func main() {
	sharedlib.ProcessRawServerData("data/nchecknetraw-server.json")
	sharedlib.ProcessRawNmapData("data/nchecknetraw-nmap.json")
}
