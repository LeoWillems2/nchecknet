package sharedlib

import (
	"encoding/json"
	"log"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
	"bufio"
)

type RawDataNmap struct {
	Nmap []string
	Hostname string
	Scanname string
	Interfacename string
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
	Interfacename string
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
	Comment      string
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
	Chain	     string
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
	data, err := os.ReadFile(filePath)
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
	data, err := os.ReadFile(filePath)
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
	nmaphost.Interfacename = rdata.Interfacename
	nmap.NmapHosts = append(nmap.NmapHosts, nmaphost)

	return nmap
}


func TestFirewall() {

	ls := TestInterfaces()
	lines, err := readLines("testdata/nft.txt")
	if err != nil {
		log.Fatalln("TestFirewall1()", err)
		return
	}

	
	l := ProcessFW(lines,ls)

 	b, _ := json.MarshalIndent(l, "", "  ")
	t := string(b)
	fmt.Println(t)
}

func TestListeners() {
	lines, err := readLines("testdata/listeners.txt")
	if err != nil {
		log.Fatalln("TestListeners()", err)
		return
	}

	l := ProcessListeners(lines)
 	b, _ := json.MarshalIndent(l, "", "  ")
	t := string(b)
	fmt.Println(t)
}

func TestInterfaces() []Interface {
	lines, err := readLines("testdata/ifconfig.txt")
	if err != nil {
		log.Fatalln("TestInterfaces()", err)
		return []Interface{}
	}

	l := ProcessInterfaces(lines)
 	//b, _ := json.MarshalIndent(l, "", "  ")
	//t := string(b)
	// fmt.Println(t)
	return l
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

		li := strings.LastIndex(fs[3], ":")
		listener.Port = fs[3][li+1:]
		tmp := fs[3][:li]
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
		log.Println(len(fi), fi)
		if len(fi) > 0 {
			listener.Bound2interface = fi[0]
		}
		Listeners = append(Listeners, listener)
	}

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


var reDport = regexp.MustCompile(`(tcp|udp) dport ([0-9]+).*accept$`)
var reInterFace = regexp.MustCompile(`iifname "([^"]+)`)
var reSaddr = regexp.MustCompile(`saddr ([0-9a-f:.]+)`)
var reDaddr = regexp.MustCompile(`daddr ([0-9a-f:.]+)`)
var reChain = regexp.MustCompile(`^\s+chain ([A-Za-z0-9-]+)`)


// ProcessFW() parses the output from nft list ruleset
func ProcessFW(fwdata []string, ifaces []Interface) []Fwrule {





	Fwrules := make([]Fwrule, 0)
	Chain := ""

	all_ifaces := []string{}
        for _, inf := range ifaces {
		all_ifaces = append(all_ifaces, inf.Name)
	}

	for _, line := range fwdata {
		fw := Fwrule{}
		fw.Intfaces = make([]string, 0)

		// step: remember the chain
		m := reChain.FindStringSubmatch(line)
		if len(m) == 2 {
			Chain = m[1]
			continue
		}

	
		// step: find proto and port with dport
		m = reDport.FindStringSubmatch(line)
		if len(m) != 3 {
			continue	// not a dport line
		}
		fw.Port = m[2]
		fw.Proto = m[1]
		fw.Ruletype = "ACCEPT"
		fw.Chain = Chain

		line = trimLeftSpace(line)
		fields := strings.Fields(line)

		// step: interfaces
		m = reInterFace.FindStringSubmatch(line)
		if len(m) == 2 {
			fw.Intfaces = append(fw.Intfaces, m[1])
		} else {
			fw.Intfaces = all_ifaces
			fw.AllIntfaces = true
		}

		// step: ipv6?
		if fields[0] == "ip6" {
			fw.IPversion = "v6"
		} else {
			fw.IPversion = "v4"
		}

		// step: get source address
		m = reSaddr.FindStringSubmatch(line)
		if len(m) == 2 {
			fw.IP_from = m[1]
		} else {
			fw.IP_from = "Any"
		}

		// step: get destination address
		m = reDaddr.FindStringSubmatch(line)
		if len(m) == 2 {
			fw.IP_to = m[1]
		} else {
			fw.IP_to = "Any"
		}

		Fwrules = append(Fwrules, fw)
	}

	return Fwrules
}

func ProcessInterfaces(interfaces []string) []Interface {
	Interfaces := make([]Interface, 0)
	Iface := Interface{}

	interfaces = append(interfaces, "\n") // fix sometimes missing last line

	haveIface := false
	for _, iface := range(interfaces) {
		if len(iface) < 10 {
			haveIface = false
			Interfaces = append(Interfaces, Iface)
			Iface = Interface{}
			continue
		}
		if haveIface {
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


// readLines reads a file and returns all lines as a slice of strings.
// It handles file opening, reading line by line, and error checking.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string //
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
