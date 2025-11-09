package main

/*
	process raw UFW rules / Interfaces / Listeners for access
		- UFW: *on interface*: does not support in or out
*/

import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	//"log"
	"fmt"
)

func main() {

	sharedlib.DBConnect()
	//sharedlib.CompareFromListeners("ABCDEF0123456789","20251106")
	//log.Println("===================")
	//sharedlib.CompareFromUFW("ABCDEF0123456789","20251106")

	t := sharedlib.GenPic("ABCDEF0123456789","20251106")
	fmt.Println(t)
}
