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

// RawDataNmap is the JSON payload posted by nmap collector scripts to /api_nmap.
type RawDataNmap struct {
	Nmap []string  // raw lines from nmap stdout
	Hostname string  // hostname of the scanning host
	Scanname string  // FQDN of the server being scanned
	Interfacename string  // interface on the server that was scanned from
	IPv string  // IP version used for the scan ("4" or "6")
	Date string  // scan timestamp (YYYY-MM-DD HH:MM:SS)
	Key string   // server auth key, verified against the servers collection
}

// RawDataServer is the JSON payload posted by server collector scripts to /api_server.
type RawDataServer struct {
	Listeners []string  // raw lines from netstat -tulpn
	Fwrules []string    // raw lines from nft list ruleset
	Interfaces []string // raw lines from ifconfig
	Routes []string     // raw lines from netstat -rn
	Hostname string     // FQDN of the monitored server
	Date string         // collection timestamp (YYYY-MM-DD HH:MM:SS)
	Key string          // server auth key, verified against the servers collection
}

// NmapLine is a single open-port entry from an nmap scan.
type NmapLine struct {
	Proto  string
	Port   string
	Status string
	Supressed bool // set by the user via the web UI to silence this finding
}

// NmapHost holds all open-port findings from one nmap run (one vantage point scanning one server interface).
type NmapHost struct {
	IPversion string       // "4" or "6"
	IPScanned string       // IP address that was scanned
	Interfacename string   // interface on the server that faces this vantage point
	FromHostname string    // hostname of the machine that ran nmap
	ScannedHostname string // FQDN of the server that was scanned
	NmapLines []NmapLine
}

// NcheckNetNmap is the parsed nmap dataset for one session; stored in the nmapdata collection.
// A single document may contain results from multiple vantage points (one NmapHost per scan run).
type NcheckNetNmap struct {
	NmapHosts []NmapHost
	Key string   // server auth key linking this to a dbServer
	Date string  // timestamp of the most-recently inserted NmapHost
}

// Listener is a single active network listener parsed from netstat -tulpn.
type Listener struct {
	IPversion       string // "v4" or "v6"
	Proto           string // "tcp", "udp", etc.
	IP              string // bound IP address; "0.0.0.0" when listening on all interfaces
	Port            string
	Bound2interface string // interface name when bound to a specific interface via %iface
	Command         string // process name from the PID/program column
	Comment         string // user annotation, persisted across sessions
	Supressed       bool   // when true, hidden from the chart unless "unhide" mode is active
}

// Interface is a network interface with its assigned addresses, parsed from ifconfig output.
type Interface struct {
	Name        string
	V4addresses []string
	V6addresses []string
	Supressed   bool
}

// Fwrule is a single nftables ACCEPT rule parsed from nft list ruleset.
// Only rules with a dport … accept pattern are captured.
type Fwrule struct {
	IPversion   string   // "v4" or "v6"
	Port        string
	Proto       string   // "tcp" or "udp"
	Intfaces    []string // interfaces this rule applies to
	AllIntfaces bool     // true when no iifname is specified (rule applies to all interfaces)
	IP_to       string   // daddr value, or "Any"
	IP_from     string   // saddr value, or "Any"
	Ruletype    string   // always "ACCEPT" for captured rules
	Chain       string   // nftables chain name (e.g. "input")
	Comment     string   // user annotation, persisted across sessions
	Supressed   bool     // when true, hidden from the chart unless "unhide" mode is active
}

// RouteEntry is a single row from the kernel routing table (netstat -rn).
type RouteEntry struct {
	Dest      string
	Gateway   string
	Interface string
	Supressed bool
}

// NcheckNetServer is the parsed server telemetry for one session; stored in the serverdata collection.
type NcheckNetServer struct {
	Date       string
	Key        string
	Hostname   string
	Listeners  []Listener
	Routes     []RouteEntry
	Fwrules    []Fwrule
	Interfaces []Interface
}

func trimLeftSpace(s string) string {
	return strings.TrimLeftFunc(s, unicode.IsSpace)
}

func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// ProcessRawServerData reads a RawDataServer JSON file and returns parsed server telemetry.
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

// ProcessRawServerDataJSON parses a RawDataServer into structured NcheckNetServer types.
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

// ProcessRawNmapData reads a RawDataNmap JSON file and returns parsed nmap results.
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


// ProcessRawNmapDataJSON parses a RawDataNmap payload into a structured NcheckNetNmap.
// Only "open" port lines after the PORT header are captured; all other nmap output is skipped.
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


// TestFirewall parses testdata/nft.txt and prints the result as JSON; used for manual testing.
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

// TestListeners parses testdata/listeners.txt and prints the result as JSON; used for manual testing.
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

// TestInterfaces parses testdata/ifconfig.txt and returns the interfaces; used for manual testing.
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

// ProcessListeners parses netstat -tulpn output into Listener structs.
// UDP lines have one fewer column (no LISTEN state), handled by the col offset.
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
		if len(fi) > 0 {
			listener.Bound2interface = fi[0]
		}
		Listeners = append(Listeners, listener)
	}

	return Listeners
}

// JsonDump serializes v to an indented JSON file at fn. Panics on marshal or write failure.
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


// Compiled regexes for ProcessFW — pre-compiled to avoid per-line allocation.
var reDport = regexp.MustCompile(`(tcp|udp) dport ([0-9]+).*accept$`)
var reInterFace = regexp.MustCompile(`iifname "([^"]+)`)
var reSaddr = regexp.MustCompile(`saddr ([0-9a-f:.]+)`)
var reDaddr = regexp.MustCompile(`daddr ([0-9a-f:.]+)`)
var reChain = regexp.MustCompile(`^\s+chain ([A-Za-z0-9-]+)`)


// ProcessFW parses nft list ruleset output into Fwrule structs.
// Only rules matching "tcp|udp dport <N> … accept" are captured; all other lines are ignored.
// When no iifname is present the rule is assumed to apply to all known interfaces.
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

// ProcessInterfaces parses ifconfig output into Interface structs.
// A blank or very short line signals the end of an interface block.
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

// ProcessRoutes parses netstat -rn output into RouteEntry structs.
// Lines before the "Dest" header and lines that don't have exactly 8 fields are skipped.
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


// FWrules2MapByPort indexes Fwrules by port number for O(1) lookup during chart generation.
func FWrules2MapByPort(fwr []Fwrule) map[string][]Fwrule {
	fwrbymap := make(map[string][]Fwrule)
	for _, r := range(fwr) {
		fwrbymap[r.Port] = append(fwrbymap[r.Port], r)
	}
	return fwrbymap
}

// Listeners2MapByPort indexes Listeners by port number for O(1) lookup during chart generation.
func Listeners2MapByPort(fwr []Listener) map[string][]Listener {
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
