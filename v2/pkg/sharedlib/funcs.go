package sharedlib

import (
	"fmt"
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
	"errors"
)


type Nmap struct {
	Proto  string
	Port   string
	Status string
}

type NmapFile struct {
	Filename  string
	IPversion string
	IPScanned string
	IPFrom string
	Nmap
}

type Listener struct {
	IPversion       string
	Proto           string
	IP              string
	Port            string
	Bound2interface string
	OriginalText    string
}

type InterfaceData struct {
	Name        string
	V4addresses []string
	V6addresses []string
}

type FWrules struct {
	IPversion    string
	Port         string
	Proto        string
	Intfaces     []string
	IP_to        string
	IP_from      string
	Ruletype     string
	Comment      string
	OriginalText string
}

type RouteEntry struct {
	Dest string
	Gateway  string
	Interface  string

}

var FWrulesByPort = make(map[string][]FWrules)
var ListenersByPort = make(map[string][]Listener)
var ListenersByRow = make([]Listener, 0)
var InterfacesByName = make(map[string]InterfaceData)
var InterfaceNames = []string{}
var NmapResults = make([]NmapFile, 0)
var RouteTable = make([]RouteEntry,0)

func trimLeftSpace(s string) string {
	return strings.TrimLeftFunc(s, unicode.IsSpace)
}

func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

func ReadUFWProc() []string {
	return ReadPipe("sudo", "/usr/sbin/ufw", "status")
}

func ReadNMAPFile(filePath string) []string {
	return ReadFile(filePath)
}

func ReadUFWFile(filePath string) []string {
	return ReadFile(filePath)
}

func ReadListenerProc() []string {
	return ReadPipe("/usr/bin/ss", "-lntup")
}

func ReadListenerFile(filePath string) []string {
	return ReadFile(filePath)
}

func ProcessNMAP(nmapdata []string, filename string) {
	nmap := NmapFile{}
	nmap.Filename = filename

	PORTseen := false
	nmap.IPversion = "v4"
	for _, line := range nmapdata {
		if strings.Contains(line, "Nmap scan report for") {
			x, _ := regexp.MatchString(`.*:.*:.*:`, line)
			if x {
				nmap.IPversion = "v6"
			}

			var re *regexp.Regexp
			if line[len(line)-1] == ')' {
				// fqdn (ip)
				re = regexp.MustCompile(`\((.*.*)\)`)
			} else {
				// ip
				re = regexp.MustCompile(`report for (.*)`)
			}
			got := re.FindStringSubmatch(line)
			nmap.IPScanned = got[1]

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
		if fs[1] != "open" {
			log.Println("can handle only open: ", line)
			continue
		}
		nmap.Status = fs[1]
		ps := strings.Split(fs[0], "/")
		nmap.Port = ps[0]
		nmap.Proto = ps[1]

		NmapResults = append(NmapResults, nmap)
	}
	JsonDump(NmapResults, "NmapResults.json")
}

func ProcessListeners(ssdata []string) {
	for _, line := range ssdata {

		listener := Listener{}

		listener.OriginalText = line

		fs := strings.Fields(line)

		if len(fs) == 0 || fs[0] == "Netid" { // Header
			continue
		}

		listener.Proto = fs[0]
		li := strings.LastIndex(fs[4], ":")
		listener.Port = fs[4][li+1:]
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
		ListenersByPort[listener.Port] = append(ListenersByPort[listener.Port], listener)
		ListenersByRow = append(ListenersByRow, listener)
	}

	JsonDump(ListenersByPort, "ListenersByPort.json")
	JsonDump(ListenersByRow, "ListenersByRow.json")
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

func ProcessUFW(ufwdata []string) {

	for _, line := range ufwdata {
		ufw := FWrules{}
		ufw.Intfaces = make([]string, 0)
		ufw.OriginalText = line

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

		switch len(topartsplit) {
		case 1: // 80/tcp
			ufw.Port = topartsplit[0]
			ufw.IP_to = "To_AnyIP"
			ufw.Intfaces = append(ufw.Intfaces, InterfaceNames...)
		case 2: // 127.0.0.1 3025/tcp  ||  3020/tcp on lo
			if strings.Contains(topartsplit[1], "ON") {
				ufw.Port = topartsplit[0]
				ufw.IP_to = "To_AnyIP"
				ufw.Intfaces = append(ufw.Intfaces, topartsplit[1])
			} else {
				ufw.Port = topartsplit[1]
				ufw.IP_to = topartsplit[0]
				ufw.Intfaces = append(ufw.Intfaces, InterfaceNames...)
			}
		case 3: // 192.168.7.7 3023/tcp on lo
			ufw.Port = topartsplit[1]
			ufw.IP_to = topartsplit[0]
			ufw.Intfaces = append(ufw.Intfaces, topartsplit[2])
		default:
			log.Fatalln("Bad split on topart term of UFW output")
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

		FWrulesByPort[ufw.Port] = append(FWrulesByPort[ufw.Port], ufw)
	}

	JsonDump(FWrulesByPort, "FWrulesByPort.json")
}

func GetInterfaces(filewrite bool) map[string]InterfaceData {

	ni, _ := net.Interfaces()
	for _, n := range ni {

		interfacedata := InterfaceData{}
		interfacedata.V4addresses = make([]string, 0)
		interfacedata.V6addresses = make([]string, 0)

		if len(n.Name) > 4 && n.Name[0:5] == "virbr" {
			//continue
		}
		if len(n.Name) > 3 && n.Name[0:4] == "vnet" {
			//continue
		}
		if n.Flags&net.FlagUp == 0 {
			continue
		}

		interfacedata.Name = n.Name
		InterfaceNames = append(InterfaceNames, n.Name)

		addrs, _ := n.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.To4() != nil {
				interfacedata.V4addresses = append(interfacedata.V4addresses, ip.String())
			} else {
				interfacedata.V6addresses = append(interfacedata.V6addresses, ip.String())
			}
		}

		InterfacesByName[interfacedata.Name] = interfacedata
	}

	if filewrite {
		JsonDump(InterfacesByName, "InterfacesByName.json")
	}

	return InterfacesByName
}

func ReadPipe(args ...string) (result []string) {
	cmd := exec.Command(args[0], args[1:]...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		log.Fatalf("Command failed to run: %v", err)
	}

	result = strings.Split(stdout.String(), "\n")

	return
}

func ReadFile(filePath string) (result []string) {
	file, err := os.Open(filePath)
	if err != nil {
		// log.Fatal prints the error and exits the program.
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return
}

func GetFQDN() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	f := strings.Split(hostname, ".")
	if len(f) < 3 {
		return hostname, errors.New("Hostname is not a FQDN")
	}
	return hostname, nil
	
}

func ReadRoutesProc() []string {
	return ReadPipe("/usr/bin/netstat", "-rn")
}

func ProcessRoutes(RouteData []string) {
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
}


func SuggestNmapLocations() {
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
}
