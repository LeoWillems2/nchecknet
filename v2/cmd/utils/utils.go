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

	os.Exit(0)
}
