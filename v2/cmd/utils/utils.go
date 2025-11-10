package main

/*
	cli utils
*/

import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"flag"
	"os"
	"log"
	"fmt"
)

var NewServer *string = flag.String("ns", "", "New Server")
var Verbose *bool = flag.Bool("v", false, "Verbose")
var ServerCollectorPy *string = flag.String("cs", "", "Create collector script for FQDN (server)")
var NmapCollectorPy *string = flag.String("cn", "", "Create collector script for Nmap-site")
var NchecknetServer *string = flag.String("NchecknetUrl", "https://nchecknet.lewi.nl", "NchecknetServer URL")

func main() {
        flag.Parse()

	sharedlib.DBConnect()

	if *NewServer != "" {
		key, err := sharedlib.CreateNewServer(*NewServer, *Verbose)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(*NewServer, key)
			os.Exit(0)
		}
	}

	if *NmapCollectorPy != "" {
		script, err := sharedlib.CreateNmapCollectorPy(*NmapCollectorPy, "eth0", *NchecknetServer)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(script)
			os.Exit(0)
		}
	}

	if *ServerCollectorPy != "" {
		script, err := sharedlib.CreateServerCollectorPy(*ServerCollectorPy, *NchecknetServer)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(script)
			os.Exit(0)
		}
	}

	os.Exit(0)
}
