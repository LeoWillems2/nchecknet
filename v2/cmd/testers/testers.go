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
var CmpUfw *bool = flag.Bool("uvp", false, "Compare UFW")
var host *string = flag.String("h", "", "Servername")
var sessionid *string = flag.String("s", "", "SessionID")

func main() {
        flag.Parse()

	sharedlib.DBConnect()

	//x , _ := sharedlib.GetLast2ServerData("monitor.managedlinux.nl")
	//log.Println(x[0].SessionID)
	//log.Println(x[1].SessionID)

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
