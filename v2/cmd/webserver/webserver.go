package main


import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"github.com/gorilla/websocket"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"net/http"
	"flag"
)

func jsonPostHandlerServerRawData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	data :=  sharedlib.RawDataServer{}
	
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	sharedlib.InsertServerData(data)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]string{"message": fmt.Sprintf("Data received successfully!")}
	
	json.NewEncoder(w).Encode(response)
}

func jsonPostHandlerNmapRawData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	data :=  sharedlib.RawDataNmap{}
	
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	sharedlib.InsertNmapData(data)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]string{"message": fmt.Sprintf("Data received successfully!")}
	
	json.NewEncoder(w).Encode(response)
}



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
					txt, buttons := sharedlib.GenPic(sn.Key,mi.SessionID)
					mo.ArrData = append(mo.ArrData,txt)
					mo.ArrData = append(mo.ArrData,buttons)
				case "GetData":
					mo.Function = "FillData"
					mo.Hostname = mi.Hostname


					t, err := sharedlib.PrettyPrintServerData("All:"+ mi.Hostname+ ":"+mi.SessionID )
					if err != nil {
						log.Println("GetData", err, mi.Hostname)
						continue
					}
					mo.ArrData = append(mo.ArrData,t)

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

var AllFunctions *bool = flag.Bool("a", false, "All Functions")

func TestH(w http.ResponseWriter, r *http.Request) {

    xfwdFor := r.Header.Get("X-Forwarded-For")
    if xfwdFor != "" {
        log.Printf("X-Forwarded-For: %s\n", xfwdFor)
    } else {
        log.Println("X-Forwarded-For header not present.")
    }
    rema := r.RemoteAddr
    if rema != "" {
        log.Printf("RemoteAddr: %s\n", rema)
    } else {
        log.Println("RemoteAddr header not present.")
    }
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
	flag.Parse()

	http.HandleFunc("/test", TestH)
	http.HandleFunc("/api_nmap", jsonPostHandlerNmapRawData)
	http.HandleFunc("/api_server", jsonPostHandlerServerRawData)

	if *AllFunctions {
		http.HandleFunc("/ws", handleWebSocket)
		//http.HandleFunc("/rawnmapcollector", handleRawNmapCollector)
		fileserver := http.FileServer(http.Dir("./webroot"))
		http.Handle("/", fileserver)
	}
	
	sharedlib.DBConnect()

	// Start the server
	port := ":8087"
	fmt.Printf("Server starting on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
