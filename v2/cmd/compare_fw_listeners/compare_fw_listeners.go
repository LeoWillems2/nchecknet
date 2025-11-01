package main

/*
        compare UFW rules / Interfaces / Listeners for gaps
	data is prepared with collectfwdata
*/

import (
	"fmt"
	"log"
	"os"
	"flag"

	//"strings"
	"encoding/json"
	"github.com/LeoWillems2/checknet/pkg/sharedlib"
)

func CompareNmapWithUFW() {
	for _, nmap := range sharedlib.NmapResults {
		ufw, ok := sharedlib.FWrulesByPort[nmap.Port]
		if !ok {
			fmt.Printf("!!!! nmap from-location %s, found port %s open, but there is no UFW rule!!\n", nmap.Filename, nmap.Port)
			continue
		}
		for _, u := range ufw {
			if u.IPversion == nmap.IPversion {
				fmt.Printf("Nmap from-location: %s, port %s, limited by UFW-from: %s\n", nmap.Filename, u.Port, u.IP_from)
			}
		}
	}
}

func ReadData() {
	/*
			// should be in compare_ufw_nmap.go
	// NmapResults
	data, err := os.ReadFile("NmapResults.json")
	if err != nil {
		log.Fatalf("Error reading NmapResults.json: %v", err)
	}
	err = json.Unmarshal(data, &sharedlib.NmapResults)
	if err != nil {
		log.Fatalf("Error unmarshalling NmapResults JSON: %v", err)
	}
	*/

	// FWrulesByPort
	data, err := os.ReadFile("FWrulesByPort.json")
	if err != nil {
		log.Fatalf("Error reading FWrulesByPort.json: %v", err)
	}
	err = json.Unmarshal(data, &sharedlib.FWrulesByPort)
	if err != nil {
		log.Fatalf("Error unmarshalling FWrulesByPort JSON: %v", err)
	}

	// ListenersByPort
	data, err = os.ReadFile("ListenersByPort.json")
	if err != nil {
		log.Fatalf("Error reading ListenersByPort.json: %v", err)
	}
	err = json.Unmarshal(data, &sharedlib.ListenersByPort)
	if err != nil {
		log.Fatalf("Error unmarshalling ListenersByPort JSON: %v", err)
	}

	// ListenersByRow
	data, err = os.ReadFile("ListenersByRow.json")
	if err != nil {
		log.Fatalf("Error reading ListenersByRow.json: %v", err)
	}
	err = json.Unmarshal(data, &sharedlib.ListenersByRow)
	if err != nil {
		log.Fatalf("Error unmarshalling ListenersByRow JSON: %v", err)
	}
}

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
	/*
	   type Listener struct {
	           IPversion string
	           Proto string
	           IP string
	           Port string
	           Bound2interface string
	           OriginalText string
	   }
	*/

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

var UfwListenFlag *bool = flag.Bool("ufw_listeners", false, "Compare ufw status <=> ss -lntup")
// var UFWNmapFlag *bool = flag.Bool("ufw_nmap", false, "Compare ufw status <=> nmap-scan")

func main() {
	ReadData()

	flag.Parse()

	if *UfwListenFlag {
		fmt.Println("================= Compare ufw status <=> ss -lntup")
		AddFW2Listeners()
	}
	/*
	if *UFWNmapFlag {
		fmt.Println("================= Compare ufw status <=> nmap-scan")
		CompareNmapWithUFW()
	}
	*/

	sharedlib.SuggestNmapLocations()
}
