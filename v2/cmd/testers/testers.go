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


	/*
	x , _ := sharedlib.GetServerDataByHostnameAndSessionID("monitor.managedlinux.nl", "20251116")
	for _, f := range x.Sdata.Fwrules{
		log.Println(x.Sdata.Date, f.Supressed)
	}
	*/

	sharedlib.GetLast2ServerData("monitor.managedlinux.nl")
	//log.Println(x[0].SessionID, x[0].Sdata.Fwrules[14].Supressed)
	//log.Println(x[1].SessionID, x[1].Sdata.Fwrules[14].Supressed)

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
