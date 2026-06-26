// Package main implements the nchecknet collector service.
//
// The collector is a lightweight HTTP server (default port 8087) that receives
// telemetry POSTed by the generated collector and nmap scripts running on
// monitored hosts. It has no HTTP-level authentication; access control relies
// entirely on the per-server key embedded in each JSON payload, which is
// verified inside sharedlib.InsertServerData / InsertNmapData.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
)

// jsonPostHandlerServerRawData handles POST /api_server.
// It decodes the RawDataServer JSON payload posted by server collector scripts
// and delegates storage and processing to sharedlib.InsertServerData.
// The server key embedded in the payload is verified inside InsertServerData.
func jsonPostHandlerServerRawData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	data := sharedlib.RawDataServer{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	sharedlib.InsertServerData(data)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Data received successfully!"})
}

// jsonPostHandlerNmapRawData handles POST /api_nmap.
// It decodes the RawDataNmap JSON payload posted by nmap collector scripts
// and delegates storage and processing to sharedlib.InsertNmapData.
// The server key embedded in the payload is verified inside InsertNmapData.
func jsonPostHandlerNmapRawData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	data := sharedlib.RawDataNmap{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	sharedlib.InsertNmapData(data)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Data received successfully!"})
}

// main loads config, connects to MongoDB, registers the two collector endpoints,
// and starts the HTTP server on the configured collector port.
// The MongoDB URL is taken from the webserver section of the config (YConfig.Server.MongoDBURL)
// because CollectorConfig does not define its own database URL.
func main() {
	YConfig, err := sharedlib.GetYamlConfig("etc/nchecknet.yml")
	if err != nil {
		log.Fatalln(err)
		return
	}

	http.HandleFunc("/api_nmap", jsonPostHandlerNmapRawData)
	http.HandleFunc("/api_server", jsonPostHandlerServerRawData)

	sharedlib.DBConnect(YConfig.Server.MongoDBURL)

	port := ":" + YConfig.Collector.Port
	fmt.Printf("Collector starting on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Collector failed to start:", err)
	}
}
