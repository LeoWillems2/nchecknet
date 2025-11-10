package sharedlib

import (
	"log"
)

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

func CompareFromUFW(key, sessionid string) {
	sd, err := GetServerDataByKeyAndSessionID(key,sessionid)
	if err != nil {
		log.Fatalln("GetServerDataByKeyAndSessionID: no doc:",key,sessionid)
		return
	}

	LbP := createLbP(sd.Sdata.Listeners);
	FbP := createFbP(sd.Sdata.Fwrules);

	compareFromUFW_(FbP,LbP)
}

func compareFromUFW_(FwrulesByPort map[string][]Fwrule,
                ListenersByPort map[string][]Listener ) {

	for fwport, fwrules := range FwrulesByPort {
		for _, fwrule := range fwrules {
			listeners, ok := ListenersByPort[fwport]
			if !ok {
				log.Printf("FW port %5s/%s (%s) is %s-ed but has no listening process\n",
					fwport, fwrule.Proto, fwrule.IP_to, fwrule.Ruletype)
				continue
			}

			for _, listener := range listeners {
				log.Printf("FW port %5s/%s (to: %s) (from: %s) is %s-ed with listener: %v\n", fwport, fwrule.Proto, fwrule.IP_to,fwrule.IP_from, fwrule.Ruletype, listener)
			}
		}
	}
}

