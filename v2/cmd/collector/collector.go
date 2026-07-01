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

// makeServerHandler returns a handler for POST /api_server.
// After inserting, it prunes old serverdata documents for that server key if
// MaxCountServerData is configured (non-zero) in the collector config.
func makeServerHandler(cfg sharedlib.CollectorConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if cfg.MaxCountServerData > 0 {
			sharedlib.PruneServerData(data.Key, cfg.MaxCountServerData)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Data received successfully!"})
	}
}

// makeNmapHandler returns a handler for POST /api_nmap.
// After inserting, it prunes old nmapdata documents for that server key if
// MaxCountNmapData is configured (non-zero) in the collector config.
func makeNmapHandler(cfg sharedlib.CollectorConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if cfg.MaxCountNmapData > 0 {
			sharedlib.PruneNmapData(data.Key, cfg.MaxCountNmapData)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Data received successfully!"})
	}
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

	http.HandleFunc("/api_nmap", makeNmapHandler(YConfig.Collector))
	http.HandleFunc("/api_server", makeServerHandler(YConfig.Collector))

	sharedlib.DBConnect(YConfig.Server.MongoDBURL)

	port := ":" + YConfig.Collector.Port
	fmt.Printf("Collector starting on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Collector failed to start:", err)
	}
}
