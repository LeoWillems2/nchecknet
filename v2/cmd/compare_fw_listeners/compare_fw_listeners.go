package main

/*
        compare UFW rules / Interfaces / Listeners for gaps
*/

import (
	"log"
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
)

/*
func CompareNmapWithUFW() {

	fwr := sharedlib.ProcessRawServerData("data/nchecknetraw-server.json")
        nmr := sharedlib.ProcessRawNmapData("data/nchecknetraw-nmap.json")

	FWrulesByPort := sharedlib.FWrules2MapByPort(fwr.Fwrules)

	for _, nmap := range nmr.NmapLines {
		ufw, ok := FWrulesByPort[nmap.Port]
		if !ok {
			log.Printf("!!!! nmap from-location XX, found port %s open, but there is no UFW rule!!\n", nmap.Port)
			continue
		}
		for _, u := range ufw {
			if u.IPversion == nmr.IPversion {
				log.Printf("Nmap from-location: XX, port %s, limited by UFW-from: %s\n", u.Port, u.IP_from)
			}
		}
	}
}
*/

func CompareFromListeners(ListenersByPort map[string][]sharedlib.FWrules,
		ListenersByPort map[string][]sharedlib.Listener ) {

	for liport, listeners := range ListenersByPort {
		for _, listener := range listeners {
			_, ok := FWrulesByPort[liport]
			if !ok {
				if listener.IP[0:4] != "127." && listener.IP != "[::1]" {
					log.Println("No FW rule for LISTEN:", listener)
				}
			}
		}
	}

}

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

func AddFW2Listeners() {
	for _, l := range sharedlib.ListenersByRow {
		if l.IP[0:4] == "127." {
			continue
		}

		iface := ""
		if l.Bound2interface != "" {
			iface = "%" + l.Bound2interface
		}
		fmt.Printf("Listener: %s%s:%s/%s\n", l.IP, iface, l.Port, l.Proto)
		fwr, ok := sharedlib.FWrulesByPort[l.Port]
		found := false
		if ok {
			for _, f := range fwr {
				if f.IPversion == l.IPversion {
					found = true
					f.OriginalText = ""
					f.Comment = ""
					fmt.Printf("\tUFW: %s %s/%s %v from: %s\n",
						f.IPversion, f.Port, f.Proto, f.Intfaces, f.IP_from)
				}
			}
		}
		if !ok || !found {
			fmt.Println("\tNo FW rule for this listener")
		}
	}
}


*/
