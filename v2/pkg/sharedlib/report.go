package sharedlib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
)

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

// old
func CompareFromListeners(key, sessionid string) {
	sd, err := GetServerDataByKeyAndSessionID(key, sessionid)
	if err != nil {
		log.Fatalln("GetServerDataByKeyAndSessionID: no doc:", key, sessionid)
		return
	}

	LbP := createLbP(sd.Sdata.Listeners)
	FbP := createFbP(sd.Sdata.Fwrules)

	compareFromListeners_(FbP, LbP)
}

// old
func compareFromListeners_(FwrulesByPort map[string][]Fwrule,
	ListenersByPort map[string][]Listener) {

	for liport, listeners := range ListenersByPort {
		for _, listener := range listeners {
			_, ok := FwrulesByPort[liport]
			if !ok {
				if (len(listener.IP) > 4) && (listener.IP[0:4] != "127." && listener.IP != "[::1]") {
					log.Println("No FW rule for LISTEN:", listener)
				}
			}
		}
	}

}

// CompareFromUFWViewpoint() and compareFromUFWViewpoint_() create the Mermaid map that depicts the fw and listeners in the Charts tab.
func CompareFromUFWViewpoint(hostname, sessionid, hide string, user dbUser) (string, error) {

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

	return compareFromUFWViewpoint_(hostname, FbP, LbP, adrs, hide, user)
}

func compareFromUFWViewpoint_(hostname string, FwrulesByPort map[string][]Fwrule,
	ListenersByPort map[string][]Listener, ifaces, hide string, user dbUser) (string, error) {

	UfwIDX := make(map[string]string)
	LisIDX := make(map[string]string)

	// clI and clB control the interactivity of the inputs and the buttons
	clI := ""
	clB := ""
	if user.AccessRight == "r" {
		clI = "readonly"
		clB = "disabled"
	}

	t := fmt.Sprintf(`<html>
<body>
<pre class=mermaid>
flowchart TD
subgraph SERVER["%s %s "]
`, hostname, ifaces)

	t += `subgraph FROM["UFW From (To) Port/Proto"]` + "\n"
	for fwport, fwrules := range FwrulesByPort {
		for _, fwrule := range fwrules {
			_, ok := ListenersByPort[fwport]
			if !ok {
				log.Println("compareFromUFWViewpoint_(): Skipping:", fwrule)
				continue
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
			x += fmt.Sprintf(`["%s (%s)<br/>%s/%s<br/>%s<br/><input class='Fwcomment formcontrol' %s style='font-size: 7pt;' id='I%s' value='%s'/> %s"]%c`, fwrule.IP_from, fwrule.IP_to, fwrule.Port, fwrule.Proto, ifas, clI, csum, fwrule.Comment, hb, '\n')
			idx := fwrule.IP_from + "-" + fwrule.IP_from + "%" + fwrule.Port + "/" + fwrule.Proto

			_, ok = UfwIDX[idx]
			if !ok {
				t += x
				UfwIDX[idx] = x
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

	for fp, ftxt := range UfwIDX {
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
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  mermaid.initialize({ startOnLoad: true });
</script>
`
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
