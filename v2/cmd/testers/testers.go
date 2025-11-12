package main

/*
	cli Testers
*/

import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"flag"
)

var Listeners *bool = flag.Bool("l", false, "Dump Listeners")

func main() {
        flag.Parse()

	sharedlib.DBConnect()

	if *Listeners {
		sharedlib.TestListeners()
	}
}
