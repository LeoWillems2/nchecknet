package main


import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"github.com/gorilla/websocket"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"net/http"
)


// Upgrader is used to upgrade HTTP connections to WebSocket connections.
var upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
                // Allow all connections by default
                return true
        },
}

// handleWebSocket handles WebSocket requests from clients.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {

	type MessageIn struct {
		Function string
		Hostname string
		SessionID string
		Data string
		Hide string
		Csum string
		ChartType string
	}

	type MessageOut struct {
		Function string
		Hostname string
		ArrData []string
	}

	// Upgrade the HTTP connection to a WebSocket connection
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
                log.Println("Upgrade error:", err)
                return
        }
        defer conn.Close()

        log.Println("Client connected")


        // Read messages from the WebSocket connection
        for {
                messageType, message, err := conn.ReadMessage()
                if err != nil {
                        log.Println("Read error:", err)
                        break
                }


                //log.Printf("Received: %s", message)
                mi := MessageIn{}
                err = json.Unmarshal(message, &mi)
                if err != nil {
                        panic(err)
                }

				log.Println(mi.Function)

				mo := MessageOut{}
				switch (mi.Function){
				case "GetServers":
					mo.Function = "FillServers"
					alls, _ := sharedlib.GetServers() 
					for _, s := range alls {
						mo.ArrData = append(mo.ArrData, s.Hostname)
					}
				case "GetSessionIDs":
					mo.Function = "FillSessionIDs"
					mo.Hostname = mi.Hostname;
					alls, _, _ := sharedlib.GetSessionIDs(mi.Hostname) 
					mo.ArrData = alls
				case "GetNmapCollector":
					mo.Function = "FillNmapCollector"
					t, _ := sharedlib.CreateNmapCollectorPy(mi.Hostname, mi.SessionID, mi.Data[4:], "https://nchecknet.lewi.nl")
					mo.ArrData = append(mo.ArrData,t)
				case "GetNmapSuggestion":
					mo.Function = "FillNmapSuggestion"
					sn, err := sharedlib.GetServerByHostname(mi.Hostname)
					
					if err != nil {
						log.Println("GetNmapSuggestion", err, mi.Hostname, sn)
						continue
					}
					mo.Hostname = mi.Hostname
					txt := sharedlib.GenPic(sn.Key,mi.SessionID)
					mo.ArrData = append(mo.ArrData,txt)
				case "GetData":
					mo.Function = "FillData"
					mo.Hostname = mi.Hostname
					t, err := sharedlib.PrettyPrintServerData("All:"+ mi.Hostname+ ":"+mi.SessionID )
					if err != nil {
						log.Println("GetData", err, mi.Hostname)
						continue
					}
					mo.ArrData = append(mo.ArrData,t)
				case "GetUfwListenChart":
					t := ""
					switch mi.ChartType {
					case "ufwlisten":
						t, err = sharedlib.CompareFromUFWViewpoint(mi.Hostname, mi.SessionID, mi.Hide)
							if err != nil {
								continue
							}	
					}
					mo.Function = "FillChartReport"
					mo.ArrData = append(mo.ArrData,t)
					
				case "HideFwrule":
					sharedlib.HideFwrule(mi.Hostname, mi.SessionID, mi.Csum)
					
					t, err := sharedlib.CompareFromUFWViewpoint(mi.Hostname, mi.SessionID,mi.Hide)
					if err != nil {
							continue
					}
					mo.Function = "FillChartReport"
					mo.ArrData = append(mo.ArrData,t)
				
				case "ChangeFwComment":
					sharedlib.ChangeFwComment(mi.Hostname, mi.SessionID, mi.Csum, mi.Data)
				}

				moj, err := json.Marshal(mo)

				if err != nil {
					log.Println("mo marshal failed", err)
					continue
				}

                // Echo the message back to the client
                if err := conn.WriteMessage(messageType, moj); err != nil {
                	log.Println("Write error:", err)
                }


        }
        log.Println("Client disconnected")
}

func createFile(name, content string) error {
	file, err := os.Create(name)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content)
	return err
}

func main() {
	http.HandleFunc("/ws", handleWebSocket)
	fileserver := http.FileServer(http.Dir("./webroot"))
	http.Handle("/", fileserver)
	
	sharedlib.DBConnect()

	// Start the server
	port := ":8086"
	fmt.Printf("Collector starting on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Collector failed to start:", err)
	}
}
