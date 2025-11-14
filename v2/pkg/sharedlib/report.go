package sharedlib

import (
	"errors"
	"log"
	"encoding/json"
	"strings"
	"fmt"

)

func PrettyPrintServerData(arg string) (string, error) {

	t := ""

	args := strings.Split(arg, ":")
	if len(args) != 3 {
		return "", errors.New("PrettyPrint() Bad argcount for -pp")
	}

	s, err := GetServerByHostname(args[1])
	if err != nil {
		return "", err
	}

	sd, err := GetServerDataByKeyAndSessionID(s.Key,args[2])
	if err != nil {
		return "", err
	}

	sd.Sdata.Key = "";
	
	switch args[0]{
	case "All":
			b, _ := json.MarshalIndent(sd.Sdata, "", "  ")

			t = string(b)

	default:
		return "", errors.New ("PrettyPrint() Bad argtype for -pp")
	}
	
	return t, nil
}



func createLbP(lis []Listener) (map[string][]Listener) {
	lbp := make(map[string][]Listener)
	for _, l := range(lis) {
		lbp[l.Port] = append(lbp[l.Port], l)
	}
	return lbp
}

func createFbP(fis []Fwrule) (map[string][]Fwrule) {
	fbp := make(map[string][]Fwrule)
	for _, f := range(fis) {
		fbp[f.Port] = append(fbp[f.Port], f)
	}
	return fbp
}

func CompareFromListeners(key, sessionid string) {
	sd, err := GetServerDataByKeyAndSessionID(key,sessionid)
	if err != nil {
		log.Fatalln("GetServerDataByKeyAndSessionID: no doc:",key,sessionid)
		return
	}

	LbP := createLbP(sd.Sdata.Listeners);
	FbP := createFbP(sd.Sdata.Fwrules);

	compareFromListeners_(FbP,LbP)
}

func compareFromListeners_(FwrulesByPort map[string][]Fwrule,
                ListenersByPort map[string][]Listener ) {
        
        for liport, listeners := range ListenersByPort {
                for _, listener := range listeners {
                        _, ok := FwrulesByPort[liport]
                        if !ok {
                                if (len(listener.IP) > 4 ) && (listener.IP[0:4] != "127." && listener.IP != "[::1]") {                                      
                                        log.Println("No FW rule for LISTEN:", listener)
                                }
                        }
                }
        }

}

func CompareFromUFWViewpoint(hostname, sessionid string) {
	sd, err := GetServerDataByHostnameAndSessionID(hostname,sessionid)
	if err != nil {
		log.Fatalln("CompareFromUFWViewpoint: no doc:",hostname,sessionid)
		return
	}

	LbP := createLbP(sd.Sdata.Listeners);
	FbP := createFbP(sd.Sdata.Fwrules);

	compareFromUFWViewpoint_(FbP,LbP)
}

func compareFromUFWViewpoint_(FwrulesByPort map[string][]Fwrule,
                ListenersByPort map[string][]Listener ) {

	UfwIDX := make(map[string]string)
	LisIDX := make(map[string]string)

	t := fmt.Sprintf(`<html>
<body>
<pre class=mermaid>
flowchart TD
subgraph SERVER["monitor.managedlinux.nl (IP's)"]
`)
	
	
	t += `subgraph FROM["UFW From (To) Port/Proto"]` + "\n"
	for fwport, fwrules := range FwrulesByPort {
		for _, fwrule := range fwrules {
			_, ok := ListenersByPort[fwport]
			if !ok {
				continue
			}
			x := fmt.Sprintf(" %s-%s-%s-%s", fwrule.IP_from, fwrule.IP_to, fwrule.Port, fwrule.Proto)
			x += fmt.Sprintf(`["%s (%s)<br/>%s/%s"]%c`, fwrule.IP_from, fwrule.IP_to, fwrule.Port, fwrule.Proto, '\n')
			_, ok = UfwIDX[fwrule.Port+"/"+fwrule.Proto]
			if !ok {
				t += x
				UfwIDX[fwrule.Port+"/"+fwrule.Proto] = x
			}
		}
	}
	t += "end\n"

	t += `subgraph COMMANDS["Commands"]` + "\n"
	for lport, listeners := range ListenersByPort {

         for _, l := range listeners {
		x := fmt.Sprintf(` L%s-%s/%s-%s`, l.Bound2interface, lport,l.Proto,l.Command)
		x += fmt.Sprintf(`["L%s-%s/%s<br/>%s"]%c`,l.Bound2interface, lport,l.Proto,l.Command, '\n')
		_, ok := LisIDX[l.Port+"/"+l.Proto]
		if  !ok {
			t += x
			LisIDX[l.Port+"/"+l.Proto] = x
		}
	 }
	}
	t += "end\n"
	t += "end\n"

	for fp, ftxt := range UfwIDX {
		ltxt, ok := LisIDX[fp]
		if ok {
		     t += fmt.Sprintf(`%s ---> %s%c`, ftxt,ltxt, '\n')
		}
	}
	
	t += `
</pre>
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  mermaid.initialize({ startOnLoad: true });
</script>
`
	fmt.Println(t)
}

