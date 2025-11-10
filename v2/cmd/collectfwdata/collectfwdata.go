package main

/*
	process raw UFW rules / Interfaces / Listeners for access
		- UFW: *on interface*: does not support in or out
*/

import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"log"
	//"fmt"
)

func main() {

	sharedlib.DBConnect()
	sharedlib.CompareFromListeners("3946588e7edb4fd3521002b8539ecf4f2a877a06830df84e488ff9c0a8f03068","20251110")
	log.Println("===================")
	sharedlib.CompareFromUFW("3946588e7edb4fd3521002b8539ecf4f2a877a06830df84e488ff9c0a8f03068","20251110")
}
