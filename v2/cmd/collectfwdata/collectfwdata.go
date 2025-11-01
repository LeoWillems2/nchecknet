package main

/*
	collect UFW rules / Interfaces / Listeners for access
		- not for routing etc.
		- on interface does not support in or out
*/

import "github.com/LeoWillems2/checknet/pkg/sharedlib"

func main() {
	sharedlib.GetInterfaces(true)
	//ProcessUFW(ReadUFWFile("ufw2.txt"))
	//ProcessListeners(ReadListenerFile("ss2.txt"))

	//for _, f := range []string{"nmap-internet2.txt"} {
		//ProcessNMAP(ReadNMAPFile(f), f)
	//}

	sharedlib.ProcessUFW(sharedlib.ReadUFWProc())
	sharedlib.ProcessListeners(sharedlib.ReadListenerProc())
}
