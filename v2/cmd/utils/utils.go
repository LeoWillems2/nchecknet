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

var YConfig sharedlib.YamlConfig

var NewServer *string = flag.String("ns", "", "New Server")
var Verbose *bool = flag.Bool("v", false, "Verbose")
var ServerCollectorPy *string = flag.String("cs", "", "Create collector script for FQDN (server)")
var PrettyPrint *string = flag.String("pp", "", "PrettyPrint [Struct:HN:SID]")

func main() {

        flag.Parse()

	var err error
        YConfig, err = sharedlib.GetYamlConfig("etc/nchecknet.yml")
        if err != nil {
                log.Fatalln(err)
                return
        }

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

	if *ServerCollectorPy != "" {
		script, err := sharedlib.CreateServerCollectorPy(*ServerCollectorPy, YConfig.Server.CollectorURL)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(script)
			os.Exit(0)
		}
	}

	if *PrettyPrint != ""{
		t, err := sharedlib.PrettyPrintServerData(*PrettyPrint)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Println("t=",t)
		os.Exit(0)

		
	}

	os.Exit(0)
}
