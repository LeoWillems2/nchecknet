package main

/*
	cli Testers
*/

import (
	"flag"
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	//"log"
)

var Listeners *bool = flag.Bool("l", false, "Dump Listeners")
var Interfaces *bool = flag.Bool("i", false, "Dump Interfaces")
var Firewall *bool = flag.Bool("f", false, "Dump Firewall")
var CmpUfw *bool = flag.Bool("uvp", false, "Compare UFW")
var host *string = flag.String("h", "", "Servername")
var sessionid *string = flag.String("s", "", "SessionID")

func main() {
	flag.Parse()

	sharedlib.DBConnect()

	if *Firewall {
		sharedlib.TestFirewall()
	}
	if *Listeners {
		sharedlib.TestListeners()
	}
	if *Interfaces {
		sharedlib.TestInterfaces()
	}

	if *CmpUfw {

		//haredlib.CompareFromUFWViewpoint(*host, *sessionid, "", u)
	}
}
