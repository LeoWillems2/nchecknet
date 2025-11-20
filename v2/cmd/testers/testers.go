package main

/*
	cli Testers
*/

import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"flag"
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

	sharedlib.TestYaml()


	if  *Firewall {
		sharedlib.TestFirewall()
	}
	if  *Listeners {
		sharedlib.TestListeners()
	}
	if *Interfaces {
		sharedlib.TestInterfaces()
	}
	if *CmpUfw {
		sharedlib.CompareFromUFWViewpoint(*host, *sessionid, "")
	}
}
