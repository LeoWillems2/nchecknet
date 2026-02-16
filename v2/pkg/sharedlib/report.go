package sharedlib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"log"
)

func compareStructs(s1, s2 interface{}) bool {
	sd1, _ := json.Marshal(s1)
	sd2, _ := json.Marshal(s2)

	return string(sd1) == string(sd2)
}

func CompareBaseline(hostname, sid string) error {
	b, err := GetBaseline(hostname)
	if err != nil {
		// no baseline, ignore
		log.Printf("No baseline for %s\n", hostname)
		return nil
	}

	return Compare2SessionIDs(hostname, b.SessionID, sid)
}


func Compare2SessionIDs(hostname, sid1,sid2 string ) error {

	sd1, err := GetServerDataByHostnameAndSessionID(hostname, sid1)
	if err != nil {
		log.Println("Compare2SessionIDs, no sid1 found")
		return err
	}

	sd2, err := GetServerDataByHostnameAndSessionID(hostname, sid2)
	if err != nil {
		log.Println("Compare2SessionIDs, no sid2 found")
		return err
	}

	// Routes
	for _, l1 := range sd1.Sdata.Routes{
		match := false
		for _, l2 := range sd2.Sdata.Routes{
			if l1 == l2 {
				match = true
				break
			}
		}
		if !match {
			log.Printf("Route disappeared: %v\n ",l1)
		}
	}
	for _, l2 := range sd2.Sdata.Routes{
		match := false
		for _, l1 := range sd1.Sdata.Routes{
			if l1 == l2 {
				match = true
				break
			}
		}
		if !match {
			log.Printf("Route appeared: %v\n ",l2)
		}
	}

	// Interfaces
	for _, l1 := range sd1.Sdata.Interfaces{
		match := false
		for _, l2 := range sd2.Sdata.Interfaces{
			if compareStructs(l1,l2) {
				match = true
				break
			}
		}
		if !match {
			log.Printf("Interface disappeared: %v\n ",l1)
		}
	}
	for _, l2 := range sd2.Sdata.Interfaces{
		match := false
		for _, l1 := range sd1.Sdata.Interfaces{
			if compareStructs(l1,l2) {
				match = true
				break
			}
		}
		if !match {
			log.Printf("Interface appeared: %v\n ",l2)
		}
	}

	// Fwrules
	for _, l1 := range sd1.Sdata.Fwrules{
		match := false
		for _, l2 := range sd2.Sdata.Fwrules{
			if compareStructs(l1,l2){
				match = true
				break
			}
		}
		if !match {
			log.Printf("Fwrule disappeared: %v\n ",l1)
		}
	}
	for _, l2 := range sd2.Sdata.Fwrules{
		match := false
		for _, l1 := range sd2.Sdata.Fwrules{
			if compareStructs(l1,l2){
				match = true
				break
			}
		}
		if !match {
			log.Printf("Fwrule appeared: %v\n ",l2)
		}
	}


	// Listeners
	for _, l1 := range sd1.Sdata.Listeners{
		match := false
		for _, l2 := range sd2.Sdata.Listeners{
			l1.Command = ""
			l2.Command = ""
			if l1 == l2 {
				match = true
				break
			}
		}
		if !match {
			log.Printf("Listener disappeared: %v\n ",l1)
		}
	}
	for _, l2 := range sd2.Sdata.Listeners{
		match := false
		for _, l1 := range sd1.Sdata.Listeners{
			l1.Command = ""
			l2.Command = ""
			if l1 == l2 {
				match = true
				break
			}
		}
		if !match {
			log.Printf("Listener appeared: %v\n ",l2)
		}
	}


	return nil
}




// PrettyPrintServerDate() creates the text for the Data tab
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

	sd, err := GetServerDataByKeyAndSessionID(s.Key, args[2])
	if err != nil {
		return "", err
	}

	sd.Sdata.Key = ""

	switch args[0] {
	case "All":
		b, _ := json.MarshalIndent(sd.Sdata, "", "  ")

		t = string(b)

	default:
		return "", errors.New("PrettyPrint() Bad argtype for -pp")
	}

	return t, nil
}

// createLbP() builds a map form the Listener array
func createLbP(lis []Listener) map[string][]Listener {
	lbp := make(map[string][]Listener)
	for _, l := range lis {
		lbp[l.Port] = append(lbp[l.Port], l)
	}
	return lbp
}

// createFbP() builds a map form the Fwrule array
func createFbP(fis []Fwrule) map[string][]Fwrule {
	fbp := make(map[string][]Fwrule)
	for _, f := range fis {
		fbp[f.Port] = append(fbp[f.Port], f)
	}
	return fbp
}

// CompareFromFWViewpoint() and compareFromFWViewpoint_() create the Mermaid map that depicts the fw and listeners in the Charts tab.
func CompareFromFWViewpoint(hostname, sessionid, hide, acright string) (string, error) {

	sd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return "", err
	}

	adrs := ""
	for _, i := range sd.Sdata.Interfaces {
		for _, a := range i.V4addresses {
			if a == "127.0.0.1" {
				//continue
			}
			adrs += "<br/>" + a + "&nbsp;&nbsp;"
		}
		for _, a := range i.V6addresses {
			if a == "::1" {
				//continue
			}
			adrs += "<br/>" + a + "&nbsp;&nbsp;"
		}
	}
	adrs = `<p style="font-size: 7pt; text-align: right;">` + adrs + `</p>`

	LbP := createLbP(sd.Sdata.Listeners)
	FbP := createFbP(sd.Sdata.Fwrules)

	return compareFromFWViewpoint_(hostname, FbP, LbP, adrs, hide, acright)
}

func compareFromFWViewpoint_(hostname string, FwrulesByPort map[string][]Fwrule,
	ListenersByPort map[string][]Listener, ifaces, hide, acright string) (string, error) {

	FwIDX := make(map[string]string)
	LisIDX := make(map[string]string)

	// clI and clB control the interactivity of the inputs and the buttons
	clI := ""
	clB := ""
	if acright == "r" {
		clI = "readonly"
		clB = "disabled"
	}

	t := fmt.Sprintf(`<pre class=mermaid>
flowchart TD
subgraph SERVER["%s %s "]
`, hostname, ifaces)

	t += `subgraph FROM["FW From (To) Port/Proto"]` + "\n"
	for fwport, fwrules := range FwrulesByPort {
		for _, fwrule := range fwrules {
			_, ok := ListenersByPort[fwport]
			if !ok {
				//log.Println("compareFromFWViewpoint_(): Skipping:", fwrule)
				//continue
			}

			T := "danger"
			Tx := "H"
			if fwrule.Supressed && hide != "unhide" {
				continue
			}

			if fwrule.Supressed && hide == "unhide" {
				T = "success"
				Tx = "U"
			}

			csum := createFwruleCsum(fwrule)

			ifas := strings.Join(fwrule.Intfaces, "-")

			hb := fmt.Sprintf(`<button style='width:5x;height:5px' class='btn btn-%s hidefwrule %s' id='%s%s'></button>`, T, clB, Tx, csum)

			x := fmt.Sprintf(" %s-%s-%s-%s", fwrule.IP_from, fwrule.IP_to, fwrule.Port, fwrule.Proto)
			x += fmt.Sprintf(`["%s (%s)<br/>%s/%s<br/>%s<br/><input class='Fwcomment formcontrol' %s style='font-size: 7pt;' id='I%s' value='%s'/> %s<br/>chain: %s"]%c`, fwrule.IP_from, fwrule.IP_to, fwrule.Port, fwrule.Proto, ifas, clI, csum, fwrule.Comment, hb, fwrule.Chain,'\n')
			idx := fwrule.IP_from + "-" + fwrule.IP_from + "%" + fwrule.Port + "/" + fwrule.Proto

			_, ok = FwIDX[idx]
			if !ok {
				t += x
				FwIDX[idx] = x
			}
		}
	}
	t += "end\n"

	t += `subgraph COMMANDS["Commands (Listeners)"]` + "\n"
	for lport, listeners := range ListenersByPort {

		for _, l := range listeners {

			T := "danger"
			Tx := "H"
			if l.Supressed && hide != "unhide" {
				continue
			}

			if l.Supressed && hide == "unhide" {
				T = "success"
				Tx = "U"
			}

			csum := createListenerCsum(l)

			hb := fmt.Sprintf(`<button style='width:5x;height:5px' class='btn btn-%s hidelistener %s' id='%s%s'></button>`, T, clB, Tx, csum)

			x := fmt.Sprintf(` %s-%s/%s-%s`, l.Bound2interface, lport, l.Proto, l.Command)

			x += fmt.Sprintf(`["%s-%s/%s<br/>%s<br/><input class='Liscomment formcontrol' %s style='font-size: 7pt;' id='L%s' value='%s'/>&nbsp;%s"]%c`,
				l.Bound2interface, lport, l.Proto, l.Command, clI, csum, l.Comment, hb, '\n')
			_, ok := LisIDX[l.Port+"/"+l.Proto]
			if !ok {
				t += x
				LisIDX[l.Port+"/"+l.Proto] = x
			}
		}
	}
	t += "end\n"
	t += "end\n"

	for fp, ftxt := range FwIDX {
		fpp := strings.Split(fp, "%")
		ltxt, ok := LisIDX[fpp[1]]
		if ok {
			if ftxt[0:4] != " 127" && ftxt[0:5] != " ::1-" {
				t += fmt.Sprintf(`%s ---> %s%c`, ftxt, ltxt, '\n')
			}
		}
	}

	t += `style FROM stroke:#FF0000,stroke-width:2px,stroke-dasharray:5 5` + "\n"
	t += `style COMMANDS stroke:#FF0000,stroke-width:2px,stroke-dasharray:5 5` + "\n"

	t += `
</pre>
`

/*
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  mermaid.initialize({ startOnLoad: true });
</script>
`
*/
	return t, nil
}

// createFwruleCsum() is used to find an fwrule by it's static fields
func createFwruleCsum(fwr Fwrule) string {

	// todo: serialize it better

	fwr.Supressed = false
	fwr.Comment = ""

	x, _ := json.Marshal(fwr)

	h := sha256.New()
	h.Write(x)

	return hex.EncodeToString(h.Sum(nil))

}

// createListenerCsum() is used to find a Listener by it's static fields
func createListenerCsum(lis Listener) string {

	// todo: serialize it better

	lis.Supressed = false
	lis.Comment = ""

	x, _ := json.Marshal(lis)

	h := sha256.New()
	h.Write(x)

	return hex.EncodeToString(h.Sum(nil))

}

func CompareFromNMAPViewpoint(hostname, sessionid string) (string, error) {

	sd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return "", err
	}
	FbP := createFbP(sd.Sdata.Fwrules)

	nm, err := GetNmapDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return "", err
	}	

	txt := "<pre class=mermaid>\nflowchart TD\n"
	for i, nmh := range nm.Ndata.NmapHosts {
		txt += fmt.Sprintf(`subgraph nmapO-%d["nmap"]%c`,i,'\n')
		txt += fmt.Sprintf(`subgraph nmap-%d["%s &rarr; %s (%s)"]%cend%c`, i,nmh.FromHostname, nmh.ScannedHostname, nmh.IPScanned, '\n', '\n' )
		txt += fmt.Sprintf(`subgraph %s["%s"]%cend%c`, nmh.Interfacename,nmh.Interfacename, '\n', '\n' )
		for j, nr := range nmh.NmapLines {

			noport := ""
			_, ok := FbP[nr.Port]
			if !ok {
				sl := fmt.Sprintf("Nmap found open port (%s) on %s but no FW port is configured", nr.Port, nmh.ScannedHostname)
                                log.Println(sl)
				noport = "<br/><span style='color:red'>No FW Port Configured!</span>"
			}

			txt += fmt.Sprintf(`subgraph nmap-%d-%d["%s/%s %s"]%cend%c`, i,j,nr.Port,nr.Proto,noport, '\n', '\n' )
			txt += fmt.Sprintf(`nmap-%d-%d ---> %s%c`,i,j,nmh.Interfacename, '\n')
		}

		txt += "end\n"
	}
	txt += "</pre>\n"

	return txt, nil
}

func RunReport(hostname, sessionid string) (string, error) {

	type R struct {
		Hostname string
		Sessionid string
		NmapWarnings []string
		FwAllowComments []string
		ListenComments []string
	}

	result := R{}

	result.Hostname = hostname
	result.Sessionid =  sessionid

	sd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return "", err
	}
	FbP := createFbP(sd.Sdata.Fwrules)

	nm, err := GetNmapDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return "", err
	}	

	for _, nmh := range nm.Ndata.NmapHosts {
		for _, nr := range nmh.NmapLines {
			_, ok := FbP[nr.Port]
			ok=false
			if !ok {
				result.NmapWarnings = append(result.NmapWarnings, fmt.Sprintf("Nmap detected unmanaged port: %s", nr.Port));
			}
		}
	}

	for _, fwr := range sd.Sdata.Fwrules {
		if fwr.Comment != "" {
			result.FwAllowComments = append(result.FwAllowComments, fmt.Sprintf("Allow port comment %s: %s (supressed: %v)", fwr.Port,fwr.Comment, fwr.Supressed))
		}
	}
	for _, li:= range sd.Sdata.Listeners {
		if li.Comment != "" {
			result.ListenComments = append(result.ListenComments, fmt.Sprintf("Listen port comment %s: %s (supressed: %v)", li.Port,li.Comment, li.Supressed))
		}
	}

	tb, _ := json.MarshalIndent(result, "", "  ")

	return string(tb), nil
}
