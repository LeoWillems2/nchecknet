package sharedlib


import (
	"io/ioutil"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"unicode"
)

type RawDataNmap struct {
	Nmap []string
	Hostname string
	Scanname string
	IPv string
	Date string
	Key string
}

type RawDataServer struct {
	Listeners []string
	Fwrules []string
	Interfaces []string
	Routes []string
	Hostname string
	Date string
	Key string
}

type NmapLine struct {
	Proto  string
	Port   string
	Status string
	Supressed bool
}

type NmapHost struct {
	IPversion string
	IPScanned string
	FromHostname string
	ScannedHostname string
	NmapLines []NmapLine
}

type NcheckNetNmap struct {
	NmapHosts []NmapHost
	Key string
	Date string
}

type Listener struct {
	IPversion       string
	Proto           string
	IP              string
	Port            string
	Bound2interface string
	Command         string
	Supressed	bool
}

type Interface struct {
	Name        string
	V4addresses []string
	V6addresses []string
	Supressed	bool
}

type Fwrule struct {
	IPversion    string
	Port         string
	Proto        string
	Intfaces     []string
	AllIntfaces bool
	IP_to        string
	IP_from      string
	Ruletype     string
	Comment      string
	Supressed	bool
}

type RouteEntry struct {
	Dest string
	Gateway  string
	Interface  string
	Supressed	bool
}

type NcheckNetServer struct {
	Date string
	Key string
	Hostname string
	Listeners []Listener
	Routes []RouteEntry
	Fwrules []Fwrule
	Interfaces []Interface
}

func trimLeftSpace(s string) string {
	return strings.TrimLeftFunc(s, unicode.IsSpace)
}

func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

func ProcessRawServerData(filePath string) NcheckNetServer {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	rdata := RawDataServer{}
	err = json.Unmarshal(data, &rdata)
	if err != nil {
		panic(err)
	}
	return ProcessRawServerDataJSON(rdata)
}

func ProcessRawServerDataJSON(rdata RawDataServer) NcheckNetServer {
	nchecknet := NcheckNetServer{}
	nchecknet.Hostname = rdata.Hostname
	nchecknet.Key = rdata.Key
	nchecknet.Date = rdata.Date

	nchecknet.Interfaces = ProcessInterfaces(rdata.Interfaces)
	nchecknet.Fwrules = ProcessFW(rdata.Fwrules, nchecknet.Interfaces)
	nchecknet.Routes = ProcessRoutes(rdata.Routes)
	nchecknet.Listeners = ProcessListeners(rdata.Listeners)

	return nchecknet
}

func ProcessRawNmapData(filePath string) NcheckNetNmap {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	rdata := RawDataNmap{}
	err = json.Unmarshal(data, &rdata)
	if err != nil {
		panic(err)
	}
	return ProcessRawNmapDataJSON(rdata)
}


func ProcessRawNmapDataJSON(rdata RawDataNmap) NcheckNetNmap {
	nmap := NcheckNetNmap{}

	nmap.Key = rdata.Key
	nmap.Date = rdata.Date

	nmaphost := NmapHost{}

	PORTseen := false
	IPversion := rdata.IPv
	IPScanned  := ""
	for _, line := range rdata.Nmap {
		if strings.Contains(line, "Nmap scan report for") {
			var re *regexp.Regexp
			if line[len(line)-1] == ')' {
				// fqdn (ip)
				re = regexp.MustCompile(`\((.*.*)\)`)
			} else {
				// ip
				re = regexp.MustCompile(`report for (.*)`)
			}
			got := re.FindStringSubmatch(line)
			IPScanned = got[1]

			continue
		}

		if len(line) > 4 && line[0:4] == "PORT" {
			PORTseen = true
			continue
		}
		if !PORTseen {
			continue
		}

		fs := strings.Fields(line)
		if len(fs) != 3 {
			continue
		}
		if fs[1] != "open" {
			log.Println("can handle only open: ", line)
			continue
		}

		nmapline := NmapLine{}

		nmapline.Status = fs[1]
		ps := strings.Split(fs[0], "/")
		nmapline.Port = ps[0]
		nmapline.Proto = ps[1]

		nmaphost.NmapLines = append(nmaphost.NmapLines, nmapline)
	}
	nmaphost.FromHostname = rdata.Hostname
	nmaphost.ScannedHostname = rdata.Scanname
	nmaphost.IPScanned = IPScanned
	nmaphost.IPversion = IPversion
	nmap.NmapHosts = append(nmap.NmapHosts, nmaphost)

	return nmap
}

func ProcessListeners(ssdata []string) []Listener {
	Listeners := make([]Listener,0)
	for _, line := range ssdata {

		listener := Listener{}


		fs := strings.Fields(line)

		if len(fs) == 0 || fs[0] == "Proto" || fs[0] == "Active" { // Header
			continue
		}

		col := 6
		if line[0] == 'u'{
			col=5		// no LISTEN col
		}
		
		listener.Command = fs[col][strings.Index(fs[col], "/")+1:]
		listener.Proto = fs[0]
		li := strings.LastIndex(fs[4], ":")
		listener.Port = fs[3][li+1:]
		tmp := fs[4][:li]
		fi := strings.SplitN(tmp, "%", 2)
		listener.IP = fi[0]
		if listener.IP == "*" {
			listener.IP = "0.0.0.0" //https://gemini.google.com/app/c87c498942ac35cd
		}
		if strings.Contains(listener.IP, ":") {
			listener.IPversion = "v6"
		} else {
			listener.IPversion = "v4"
		}
		if len(fi) > 1 {
			listener.Bound2interface = fi[1]
		}
		Listeners = append(Listeners, listener)
	}

	//JsonDump(ListenersByPort, "ListenersByPort.json")
	//JsonDump(ListenersByRow, "ListenersByRow.json")

	return Listeners
}

func JsonDump(i interface{}, fn string) {
	jsonBytes, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling %s to JSON: %v", fn, err)
	}
	err = os.WriteFile(fn, jsonBytes, 0644)
	if err != nil {
		log.Fatalln("Error writing data to file", fn, err)
	}
}

func ProcessFW(fwdata []string, ifaces []Interface) []Fwrule {

	Fwrules := make([]Fwrule, 0)

	for _, line := range fwdata {
		ufw := Fwrule{}
		ufw.Intfaces = make([]string, 0)


		switch {
		case strings.Contains(line, "ALLOW"):
			ufw.Ruletype = "ALLOW"
		case strings.Contains(line, "BLOCK"):
			ufw.Ruletype = "BLOCK"
		case strings.Contains(line, "DROP"):
			ufw.Ruletype = "DROP"
		case strings.Contains(line, "REJECT"):
			ufw.Ruletype = "REJECT"
		default:
			continue
		}

		// store and remove Comment
		ufw.Comment = ""
		cmtindex := strings.Index(line, "#")
		if cmtindex != -1 {
			ufw.Comment = line[cmtindex:]
			line = line[0:cmtindex]
		}

		//exception......
		switch {
		case strings.Contains(line, " in "):
			fallthrough
		case strings.Contains(line, " out "):
			log.Println("Cowardly skipping lines with in/out:", line)

		}

		// sanitize
		firstsplit := strings.Split(line, ufw.Ruletype)
		topart := trimLeftSpace(firstsplit[0])
		frompart := trimLeftSpace(firstsplit[1])
		topart = trimRightSpace(topart)
		frompart = trimRightSpace(frompart)

		// test IPv6
		ufw.IPversion = "v4"
		switch {
		case strings.Contains(topart, " (v6)"):
			topart = strings.Replace(topart, " (v6)", "", 1)
			ufw.IPversion = "v6"
			fallthrough
		case strings.Contains(frompart, " (v6)"):
			frompart = strings.Replace(frompart, " (v6)", "", 1)
			ufw.IPversion = "v6"
			fallthrough
		case strings.Contains(topart, ":"):
			fallthrough
		case strings.Contains(frompart, ":"):
			ufw.IPversion = "v6"
		}

		// process topart
		topart = strings.Replace(topart, "on ", "ON", 1) // unique
		topartsplit := strings.SplitN(topart, " ", 3)
		
		all_ifaces := []string{}
		for _, inf := range ifaces {
			all_ifaces = append(all_ifaces, inf.Name)
		}

		switch len(topartsplit) {
		case 1: // 80/tcp
			ufw.Port = topartsplit[0]
			ufw.IP_to = "To_AnyIP"
			ufw.Intfaces = append(ufw.Intfaces, all_ifaces...)
			ufw.AllIntfaces = true
		case 2: // 127.0.0.1 3025/tcp  ||  3020/tcp on lo
			if strings.Contains(topartsplit[1], "ON") {
				ufw.Port = topartsplit[0]
				ufw.IP_to = "To_AnyIP"
				ufw.Intfaces = append(ufw.Intfaces, topartsplit[1])
			} else {
				ufw.Port = topartsplit[1]
				ufw.IP_to = topartsplit[0]
				ufw.Intfaces = append(ufw.Intfaces, all_ifaces...)
				ufw.AllIntfaces = true
			}
		case 3: // 192.168.7.7 3023/tcp on lo
			ufw.Port = topartsplit[1]
			ufw.IP_to = topartsplit[0]
			ufw.Intfaces = append(ufw.Intfaces, topartsplit[2])
		default:
			log.Fatalln("Bad split on topart term of FW output")
		}

		// process port and proto
		switch {
		case strings.Contains(ufw.Port, "/tcp"):
			ufw.Proto = "tcp"
			ufw.Port = strings.Replace(ufw.Port, "/tcp", "", 1)
		case strings.Contains(ufw.Port, "/udp"):
			ufw.Proto = "udp"
			ufw.Port = strings.Replace(ufw.Port, "/udp", "", 1)
		default:
			log.Println("Bad proto on line: ", line)
		}

		// sanitize
		for i := range ufw.Intfaces {
			ufw.Intfaces[i] = strings.Replace(ufw.Intfaces[i], "ON", "", 1)
		}

		// Process ufw "From"
		ufw.IP_from = frompart

		Fwrules = append(Fwrules, ufw)
	}

	return Fwrules
}

func ProcessInterfaces(interfaces []string) []Interface {
	Interfaces := make([]Interface, 0)
	Iface := Interface{}

	haveIface := false
	for _, iface := range(interfaces) {
		if len(iface) < 10 {
			haveIface = false
			Interfaces = append(Interfaces, Iface)
			Iface = Interface{}
			continue
		}
		if haveIface == true {
			// scan for inet and inet6
			fs := strings.Fields(trimLeftSpace(iface))
			switch fs[0] {
			 case "inet":
				Iface.V4addresses = append(Iface.V4addresses, fs[1])
			 case "inet6":
				Iface.V6addresses = append(Iface.V6addresses, fs[1])
			}
			continue
		}
		if iface[0] != ' ' {
			haveIface = true
			fs := strings.Fields(iface)
			Iface.Name = strings.Replace(fs[0], ":", "", 1)
			continue
		}
		haveIface = false
	}

	return Interfaces
}

func ProcessRoutes(RouteData []string) []RouteEntry {
	RouteTable := make([]RouteEntry,0)
	entry := RouteEntry{}
	DestSeen := false
	for _, line := range(RouteData) {
		if len(line) > 3 && line[0:4] == "Dest" {
			DestSeen = true
			continue
		}
		if !DestSeen {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 8 {
			continue
		}
		entry.Dest = f[0]
		entry.Gateway = f[1]
		entry.Interface = f[7]

		RouteTable = append(RouteTable, entry)
	}
	return RouteTable
}


func SuggestNmapLocations() {
/*
	//ifaces := GetInterfaces(false)
	hostname, err := GetFQDN()
	if err != nil {
		log.Println("Warning:", err)
	}

	ProcessRoutes(ReadRoutesProc())

	for _, r := range(RouteTable) {
		iface := GetInterfaces(false)[r.Interface]
		for _, a := range(iface.V4addresses) {
			fmt.Printf("On a host behind %s/%s, run nmapscanner -s %s -k %s\n", r.Interface,r.Dest, a, hostname)
		}
		for _, a := range(iface.V6addresses) {
			fmt.Printf("On a host behind %s/%s, run nmapscanner -s %s -k %s\n", r.Interface,r.Dest, a, hostname)
		}
		continue
	}
*/
} 


/*
func DumpData() {
	type T struct {
	    S NcheckNetServer
	    N NcheckNetNmap
	}
	t := T{}

	t.S = ProcessRawServerData("data/nchecknetraw-server.json")
        t.N = ProcessRawNmapData("data/nchecknetraw-nmap.json")

	JsonDump(t, "testdump.json")
}
*/

func FWrules2MapByPort(fwr []Fwrule) map[string][]Fwrule {
	fwrbymap := make(map[string][]Fwrule)
	for _, r := range(fwr) {
		fwrbymap[r.Port] = append(fwrbymap[r.Port], r)
	}
	return fwrbymap
}

func Listeners2MapByPort(fwr []Listener) map[string][]Listener{
	lisbymap := make(map[string][]Listener)
	for _, r := range(fwr) {
		lisbymap[r.Port] = append(lisbymap[r.Port], r)
	}
	return lisbymap
}
