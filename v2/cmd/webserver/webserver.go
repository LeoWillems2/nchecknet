package main

import (
	"github.com/LeoWillems2/nchecknet/pkg/sharedlib"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func main() {
	http.HandleFunc("/api_nmap", jsonPostHandlerNmapRawData)
	http.HandleFunc("/api_server", jsonPostHandlerServerRawData)
	
	sharedlib.DBConnect()

	// Start the server
	port := ":8080"
	fmt.Printf("Server starting on port %s\n", port)
	
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
