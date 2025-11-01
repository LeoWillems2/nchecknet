package main

import (
	"flag"
	"fmt"
	"os"
	//"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
)

func main() {

	IPtoscan := flag.String("t", "", "Target IP address to scan")
	flag.Parse()

	hostname, err := os.Hostname()
	fmt.Println("->", *IPtoscan, hostname, err)

}
