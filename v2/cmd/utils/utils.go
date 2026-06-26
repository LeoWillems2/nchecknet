// Package main implements the nchecknet CLI admin tool.
//
// utils connects directly to MongoDB (via sharedlib) and is used for
// bootstrapping and day-to-day operations: creating users and servers,
// generating collector/nmap scripts, setting baselines, and running reports.
// All output goes to stdout; errors go to stderr via log.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
)

// YConfig holds the configuration loaded from etc/nchecknet.yml at startup.
var YConfig sharedlib.YamlConfig

// Baseline / session flags.
var Baseline *string = flag.String("sb", "", "Set baseline: -sb hostname -i sessionid")
var Ident *string = flag.String("i", "", "Ident")
var Ident2 *string = flag.String("i2", "", "Compare 2 Sessions: -i s1 -i2 s2 -s fqdn")
var Report *bool = flag.Bool("r", false, "Report")

// Server / script flags.
var Server *string = flag.String("s", "", "Server FQDN")
var NewServer *string = flag.String("ns", "", "New Server, add: -O")
var ServerCollectorPy *string = flag.String("cs", "", "Create collector script for FQDN (server)")
var NmapCollectorPy *bool = flag.Bool("nm", false, "Create nmapcollector script for FQDN (server), use: -i ident  -if iface -s server -cl nchecknetserver")
var Iface *string = flag.String("if", "", "Interface")

// User flags.
var NewUser *string = flag.String("nu", "", "New User: -nu username -P password -O owner -R [awr]")
var Password *string = flag.String("P", "", "Password")
var Owner *string = flag.String("O", "", "Owner")
var Rights *string = flag.String("R", "", "Rights")

// Misc flags.
var PrettyPrint *string = flag.String("pp", "", "PrettyPrint [Struct:HN:SID]")

// main parses flags, loads config, connects to MongoDB, then dispatches to the
// appropriate sharedlib call based on which flag was set. Each branch exits after
// completing its action; reaching the end of main is a no-op success exit.
func main() {
	flag.Parse()

	var err error
	YConfig, err = sharedlib.GetYamlConfig("etc/nchecknet.yml")
	if err != nil {
		log.Fatalln(err)
		return
	}

	sharedlib.DBConnect(YConfig.Server.MongoDBURL)

	// -nm: generate and print the nmap collector script for an interface.
	if *NmapCollectorPy {
		s, err := sharedlib.CreateNmapCollectorPy(*Server, *Ident, *Iface, YConfig.Collector.CollectorURL)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(s)
		return
	}

	// -sb: mark a session as the baseline for a host; requires -i.
	if *Baseline != "" {
		if *Ident == "" {
			log.Fatalln("-sb: missing -i (session id)")
			return
		}
		err := sharedlib.SetBaseline(*Baseline, *Ident)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	// -i2: diff two sessions for the same host; requires -i (sid1) and -s.
	if *Ident2 != "" {
		sharedlib.Compare2SessionIDs(*Server, *Ident, *Ident2)
		return
	}

	// -r: print a JSON report and log any nmap discrepancies to stderr.
	if *Report {
		if *Server == "" || *Ident == "" {
			log.Fatalln("-r (Report): missing -s and/or -i")
			return
		}
		t, err := sharedlib.RunReport(*Server, *Ident)
		if err != nil {
			log.Fatalln("-r (Report): failed", err)
			return
		}
		fmt.Println(t)
		// Log nmap vs firewall discrepancies to stderr.
		sharedlib.CompareFromNMAPViewpoint(*Server, *Ident)
		return
	}

	// -nu: create a new user; requires -P, -O, and -R.
	if *NewUser != "" {
		_, err := sharedlib.CreateUser(*NewUser, *Password, *Owner, *Rights)
		if err != nil {
			log.Println(err)
		}
	}

	// -ns: register a new server and print its generated auth key; requires -O.
	if *NewServer != "" {
		key, err := sharedlib.CreateNewServer(*NewServer, *Owner)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(*NewServer, key)
			os.Exit(0)
		}
	}

	// -cs: generate and print the server collector script for a given FQDN.
	if *ServerCollectorPy != "" {
		script, err := sharedlib.CreateServerCollectorPy(*ServerCollectorPy, YConfig.Collector.CollectorURL)
		if err != nil {
			log.Println(err)
			os.Exit(2)
		} else {
			fmt.Println(script)
			os.Exit(0)
		}
	}

	// -pp: pretty-print stored server data; arg format is "Struct:hostname:sessionid".
	if *PrettyPrint != "" {
		t, err := sharedlib.PrettyPrintServerData(*PrettyPrint)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Println("t=", t)
		os.Exit(0)
	}

	os.Exit(0)
}
