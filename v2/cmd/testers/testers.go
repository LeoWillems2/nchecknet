package main

/*
	cli Testers
*/

import (
	"flag"
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"log"
	"fmt"
)

var Listeners *bool = flag.Bool("l", false, "Dump Listeners")
var Interfaces *bool = flag.Bool("i", false, "Dump Interfaces")
var Firewall *bool = flag.Bool("f", false, "Dump Firewall")
var CmpFw *bool = flag.Bool("uvp", false, "Compare FW")
var CmpNmap *bool = flag.Bool("nmap", false, "Compare nmap")
var host *string = flag.String("h", "", "Servername")
var sessionid *string = flag.String("s", "", "SessionID")

func main() {
	flag.Parse()


        YConfig, err := sharedlib.GetYamlConfig("etc/nchecknet.yml")
        if err != nil {
                log.Fatalln(err)
                return
        }

        sharedlib.DBConnect(YConfig.Server.MongoDBURL)


	if *Firewall {
		sharedlib.TestFirewall()
	}
	if *Listeners {
		sharedlib.TestListeners()
	}
	if *Interfaces {
		sharedlib.TestInterfaces()
	}

	if *CmpFw {

		m, err := sharedlib.CompareFromFWViewpoint(*host, *sessionid, "", "w")
		if err == nil {
			fmt.Println(m)
		} else {
			log.Println(err)
		}
		return
	}

	if *CmpNmap {
		sharedlib.CompareFromNMAPViewpoint(*host, *sessionid)
	}
}
