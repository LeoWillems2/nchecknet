package main

/*
        compare UFW rules / Interfaces / Listeners for gaps
	data is prepared with collectfwdata
*/

import (
	"fmt"
	"flag"
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
)

func CompareNmapWithUFW() {

	fwr := sharedlib.ProcessRawServerData("data/nchecknetraw-server.json")
        nmr := sharedlib.ProcessRawNmapData("data/nchecknetraw-nmap.json")

	FWrulesByPort := sharedlib.FWrules2MapByPort(fwr.Fwrules)
	//Listeners2MapByPort


	for _, nmap := range nmr.NmapLines {
		ufw, ok := FWrulesByPort[nmap.Port]
		if !ok {
			fmt.Printf("!!!! nmap from-location XX, found port %s open, but there is no UFW rule!!\n", nmap.Port)
			continue
		}
		for _, u := range ufw {
			if u.IPversion == nmr.IPversion {
				fmt.Printf("Nmap from-location: XX, port %s, limited by UFW-from: %s\n", u.Port, u.IP_from)
			}
		}
	}
}

/*
func CompareFromListeners() {
	for liport, listeners := range sharedlib.ListenersByPort {
		for _, listener := range listeners {
			_, ok := sharedlib.FWrulesByPort[liport]
			if !ok {
				if listener.IP[0:4] != "127." && listener.IP != "[::1]" {
					log.Println("No FW rule for LISTEN:", listener)
				}
			}
		}
	}
}
*/

/*
func CompareFromUFW() {
	for fwport, fwrules := range sharedlib.FWrulesByPort {
		for _, fwrule := range fwrules {
			listeners, ok := sharedlib.ListenersByPort[fwport]
			if !ok {
				log.Printf("FW port %5s/%s (%s) is %s-ed but has no listening process\n",
					fwport, fwrule.Proto, fwrule.IP_to, fwrule.Ruletype)
				continue
			}

			for _, listener := range listeners {
				log.Printf("FW port %5s/%s (%s) is %s-ed with listener: %v\n", fwport, fwrule.Proto, fwrule.IP_to, fwrule.Ruletype, listener)
			}
		}
	}
}
*/

var UfwListenFlag *bool = flag.Bool("ufw_listeners", false, "Compare ufw status <=> ss -lntup")
// var UFWNmapFlag *bool = flag.Bool("ufw_nmap", false, "Compare ufw status <=> nmap-scan")

func main() {
	flag.Parse()

	/*
	if *UfwListenFlag {
		fmt.Println("================= Compare ufw status <=> ss -lntup")
		AddFW2Listeners()
	}
	if *UFWNmapFlag {
		fmt.Println("================= Compare ufw status <=> nmap-scan")
		CompareNmapWithUFW()
	}
	*/

	//sharedlib.SuggestNmapLocations()
}
