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

var NewUser *string = flag.String("nu", "", "New User, add: -P -O -R")
var Password *string = flag.String("P", "", "Password")
var Owner *string = flag.String("O", "", "Owner")
var Rights *string = flag.String("R", "", "Rights")

var Report *bool = flag.Bool("r", false, "Report")
var Server *string = flag.String("s", "", "Server FQDN")
var Ident *string = flag.String("i", "", "Ident")

var NewServer *string = flag.String("ns", "", "New Server, add: -O")
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

	sharedlib.DBConnect(YConfig.Server.MongoDBURL)

	if (*Report) {
		if (*Server == "" || *Ident == "" ) {
			log.Fatalln("-r (Report): missing -s and/or -i");
			return;
		}
		t, err := sharedlib.RunReport(*Server, *Ident);
		if err != nil {
			log.Fatalln("-r (Report): failed", err);
			return;
		}
		fmt.Println(t)
		return;
	}


	if *NewUser != "" {


		// check -P -R -O


		_, err := sharedlib.CreateUser(*NewUser, *Password, *Owner, *Rights)
		if  err != nil {
			log.Println(err)
		}
	}

	if *NewServer != "" {

		// check -O

		key, err := sharedlib.CreateNewServer(*NewServer, *Owner)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(*NewServer, key)
			os.Exit(0)
		}
	}

	if *ServerCollectorPy != "" {
		script, err := sharedlib.CreateServerCollectorPy(*ServerCollectorPy, YConfig.Collector.CollectorURL)
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
