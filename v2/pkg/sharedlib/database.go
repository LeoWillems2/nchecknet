package sharedlib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// dbBaseline is the MongoDB document stored in the baseline collection.
type dbBaseline struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Hostname     string             `bson:"hostname,omitempty"`
	SessionID string             `bson:"sessionid,omitempty"`
}

// dbUser is the MongoDB document stored in the users collection.
type dbUser struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Name         string             `bson:"name,omitempty"`
	PassHash     string             `bson:"passhash,omitempty"`
	AccessRight  string             `bson:"accessright,omitempty"`
	Owner        string             `bson:"owner,omitempty"`
	Active       bool               `bson:"active,omitempty"`
	DateInserted string             `bson:"dateinserted,omitempty"`
	Token        string             `bson:"token,omitempty"`
}

// dbServer is the MongoDB document stored in the servers collection.
type dbServer struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Hostname     string             `bson:"hostname,omitempty"`
	CustomerID   string             `bson:"customerid,omitempty"`
	Key          string             `bson:"key,omitempty"`
	DateInserted string             `bson:"dateinserted,omitempty"`
	Owner        string             `bson:"owner,omitempty"`
	Active       bool               `bson:"active,omitempty"`
}

// dbServerData is the MongoDB document stored in the serverdata collection (one per server per day).
type dbServerData struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	SessionID string             `bson:"sessionid,omitempty"`
	Key       string             `bson:"key,omitempty"`
	Sdata     NcheckNetServer    `bson:"sdata,omitempty"`
}

// dbNmapData is the MongoDB document stored in the nmapdata collection (one per server per day,
// potentially holding results from multiple vantage points).
type dbNmapData struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	SessionID string             `bson:"sessionid,omitempty"`
	Key       string             `bson:"key,omitempty"`
	Ndata     NcheckNetNmap      `bson:"ndata,omitempty"`
}

// dbServerAlert is the MongoDB document stored in the ServerAlerts collection.
type dbServerAlert struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	InfoType string             `bson:"InfoType"`
	Data     interface{}        `bson:"Data"`
	What     string             `bson:"What"`
	Hostname string             `bson:"Hostname"`
	Sid1     string             `bson:"Sid1"`
	Sid2     string             `bson:"Sid2"`
	DataHash string             `bson:"DataHash"`
}

// MongoDB collection handles, initialised by DBConnect.
var ServersCollection *mongo.Collection
var ServerDataCollection *mongo.Collection
var NmapDataCollection *mongo.Collection
var UsersCollection *mongo.Collection
var BaselineCollection *mongo.Collection
var ServerAlertsCollection *mongo.Collection

// ctx is the package-level background context used for all MongoDB operations.
var ctx = context.Background()

// DBConnect opens a MongoDB connection and initialises the package-level collection handles.
// Calls log.Fatalf on connection or ping failure.
func DBConnect(uri string) (*mongo.Client, error) {
	clientCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(clientCtx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	if err = client.Ping(clientCtx, nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	ServersCollection = client.Database("nchecknet").Collection("servers")
	ServerDataCollection = client.Database("nchecknet").Collection("serverdata")
	NmapDataCollection = client.Database("nchecknet").Collection("nmapdata")
	UsersCollection = client.Database("nchecknet").Collection("users")
	BaselineCollection = client.Database("nchecknet").Collection("baseline")
	ServerAlertsCollection = client.Database("nchecknet").Collection("ServerAlerts")

	return client, nil
}

// InsertServerAlert stores an alert document in the ServerAlerts collection,
// skipping the insert if an identical document already exists.
func InsertServerAlert(hostname, sid1, sid2, infoType, what string, data interface{}) error {
	b, _ := json.Marshal(data)
	h := sha256.New()
	h.Write([]byte(hostname + sid1 + sid2 + infoType + what))
	h.Write(b)
	dataHash := hex.EncodeToString(h.Sum(nil))

	var existing dbServerAlert
	err := ServerAlertsCollection.FindOne(ctx, bson.M{"DataHash": dataHash}).Decode(&existing)
	if err == nil {
		return nil
	}
	if err != mongo.ErrNoDocuments {
		return err
	}

	doc := dbServerAlert{
		InfoType: infoType,
		Data:     data,
		What:     what,
		Hostname: hostname,
		Sid1:     sid1,
		Sid2:     sid2,
		DataHash: dataHash,
	}
	_, err = ServerAlertsCollection.InsertOne(ctx, doc)
	return err
}

// GetNmapDataByHostnameAndSessionID fetches nmap data for a hostname and session, resolving the hostname to a key first.
func GetNmapDataByHostnameAndSessionID(hostname, sessionid string) (dbNmapData, error) {
	s, err := GetServerByHostname(hostname)
	if err != nil {
		return dbNmapData{}, err
	}
	return GetNmapDataByKeyAndSessionID(s.Key, sessionid)

}

// GetNmapDataByKeyAndSessionID fetches the nmapdata document for the given server key and session ID.
func GetNmapDataByKeyAndSessionID(key, sessionid string) (dbNmapData, error) {
	filter := bson.M{"key": key, "sessionid": sessionid}
	nmap := dbNmapData{}
	err := NmapDataCollection.FindOne(ctx, filter).Decode(&nmap)
	return nmap, err
}

// GetServerDataByHostnameAndSessionID fetches server data for a hostname and session, resolving the hostname to a key first.
func GetServerDataByHostnameAndSessionID(hostname, sessionid string) (dbServerData, error) {
	s, err := GetServerByHostname(hostname)
	if err != nil {
		log.Printf("GetServerDataByHostnameAndSessionID failed: [%s][%s]%v\n", hostname, sessionid, err)
		return dbServerData{}, err
	}

	return GetServerDataByKeyAndSessionID(s.Key, sessionid)
}

// GetServerDataByKeyAndSessionID fetches the serverdata document for the given server key and session ID.
func GetServerDataByKeyAndSessionID(key, sessionid string) (dbServerData, error) {
	filter := bson.M{"key": key, "sessionid": sessionid}
	server := dbServerData{}
	err := ServerDataCollection.FindOne(ctx, filter).Decode(&server)
	return server, err
}

// GetServers returns all servers visible to user: all servers for admins, owner-scoped for others.
func GetServers(user dbUser) ([]dbServer, error) {
	sd := []dbServer{}

	filter := bson.M{"owner": user.Owner}
	if user.AccessRight == "a" {
		filter = bson.M{}
	}

	cursor, err := ServersCollection.Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}

	if err = cursor.All(ctx, &sd); err != nil {
		log.Println(err)
	}
	return sd, err
}

// GetSessionIDs returns all stored session IDs for hostname, plus the server's auth key.
func GetSessionIDs(hostname string) ([]string, string, error) {
	ss := []string{}

	s, err := GetServerByHostname(hostname)
	if err != nil {
		log.Fatal(err)
	}

	filter := bson.M{"key": s.Key}
	cursor, err := ServerDataCollection.Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}

	for cursor.Next(ctx) {
		sd := dbServerData{}
		if err = cursor.Decode(&sd); err != nil {
			log.Fatal(err)
		}
		ss = append(ss, sd.SessionID)
	}
	if err := cursor.Err(); err != nil {
		log.Println(err)
	}

	return ss, s.Key, err
}

// GetLast2ServerData returns the two most recent server data documents for hostname (index 0=older, 1=newer).
// Used to carry over Comment and Supressed flags when a new session is inserted.
func GetLast2ServerData(hostname string) ([]dbServerData, error) {

	sds := make([]dbServerData, 2)

	s, err := GetServerByHostname(hostname)
	if err != nil {
		log.Println("Error finding server:", err)
		return sds, err
	}

	filter := bson.M{"key": s.Key}
	cursor, err := ServerDataCollection.Find(ctx, filter)
	if err != nil {
		log.Println("Error finding documents:", err)
		return sds, err
	}
	for cursor.Next(ctx) {
		sd := dbServerData{}
		if err := cursor.Decode(&sd); err != nil {
			log.Println("Error decoding document:", err)
			return sds, err
		}
		sds[0] = sds[1]
		sds[1] = sd
	}

	if err := cursor.Err(); err != nil {
		log.Println("Cursor iteration error:", err)
		return sds, err
	}

	return sds, err
}

// ChangeFwComment sets the Comment on the firewall rule identified by csum (SHA-256 checksum with leading type byte).
func ChangeFwComment(hostname, sessionid, csum, comment string) error {
	dbsd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return err
	}

	for i, fwr := range dbsd.Sdata.Fwrules {
		tc := createFwruleCsum(fwr)
		if tc == csum[1:] {

			dbsd.Sdata.Fwrules[i].Comment = comment

			// Update
			update := bson.D{
				{Key: "$set", Value: bson.D{
					{Key: "sdata", Value: dbsd.Sdata},
				}},
			}

			_, err = ServerDataCollection.UpdateByID(ctx, dbsd.ID, update)
			if err != nil {
				log.Println("Error updating document in ServerDataCollection:", err)
			}
			return err

		}
	}

	return errors.New("Fwrule() not found " + hostname + " " + sessionid)
}

// ChangeLisComment sets the Comment on the listener identified by csum (SHA-256 checksum with leading type byte).
func ChangeLisComment(hostname, sessionid, csum, comment string) error {
	dbsd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return err
	}

	for i, lis := range dbsd.Sdata.Listeners {
		tc := createListenerCsum(lis)
		if tc == csum[1:] {

			dbsd.Sdata.Listeners[i].Comment = comment

			// Update
			update := bson.D{
				{Key: "$set", Value: bson.D{
					{Key: "sdata", Value: dbsd.Sdata},
				}},
			}

			_, err = ServerDataCollection.UpdateByID(ctx, dbsd.ID, update)
			if err != nil {
				log.Println("Error updating document in ServerDataCollection:", err)
			}
			return err

		}
	}

	return errors.New("Listener() not found " + hostname + " " + sessionid)
}

// HideFwrule toggles the Supressed flag on the firewall rule identified by csum.
// csum[0]=='H' suppresses; any other prefix un-suppresses.
func HideFwrule(hostname, sessionid, csum string) error {
	dbsd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return err
	}

	for i, fwr := range dbsd.Sdata.Fwrules {
		tc := createFwruleCsum(fwr)
		if tc == csum[1:] {

			if csum[0] == 'H' {
				dbsd.Sdata.Fwrules[i].Supressed = true
			} else {
				dbsd.Sdata.Fwrules[i].Supressed = false
			}

			// Update
			update := bson.D{
				{Key: "$set", Value: bson.D{
					{Key: "sdata", Value: dbsd.Sdata},
				}},
			}

			_, err = ServerDataCollection.UpdateByID(ctx, dbsd.ID, update)
			if err != nil {
				log.Println("Error updating document in ServerDataCollection:", err)
			}
			return err

		}
	}

	return errors.New("HideFwrule() not found " + hostname + " " + sessionid)
}

// HideListener toggles the Supressed flag on the listener identified by csum.
// csum[0]=='H' suppresses; any other prefix un-suppresses.
func HideListener(hostname, sessionid, csum string) error {
	dbsd, err := GetServerDataByHostnameAndSessionID(hostname, sessionid)
	if err != nil {
		return err
	}

	for i, lis := range dbsd.Sdata.Listeners {

		tc := createListenerCsum(lis)
		if tc == csum[1:] {

			if csum[0] == 'H' {
				dbsd.Sdata.Listeners[i].Supressed = true
			} else {
				dbsd.Sdata.Listeners[i].Supressed = false
			}

			// Update
			update := bson.D{
				{Key: "$set", Value: bson.D{
					{Key: "sdata", Value: dbsd.Sdata},
				}},
			}

			_, err = ServerDataCollection.UpdateByID(ctx, dbsd.ID, update)
			if err != nil {
				log.Println("Error updating document in ServerDataCollection:", err)
			}
			return err

		}
	}

	return errors.New("HideListener() not found " + hostname + " " + sessionid)
}

// DeleteExistingServerDataIfExists removes the server data document matching hostname+key+sessionid.
// Called before each insert so daily re-runs from cron are idempotent.
func DeleteExistingServerDataIfExists(hostname, key, sessionid string) {
	filter := bson.M{"sdata.hostname": hostname, "sdata.key": key, "sessionid": sessionid}
	// feitelijk hoeft de lookup niet.

	serverdata := dbServerData{}
	err := ServerDataCollection.FindOne(ctx, filter).Decode(&serverdata)

	if err == nil {
		ServerDataCollection.DeleteOne(ctx, filter)
		//log.Println("Serverdata deleted")
	}
}

// GetServerByHostname finds a server document by FQDN.
func GetServerByHostname(hostname string) (dbServer, error) {
	filter := bson.M{"hostname": hostname}
	server := dbServer{}
	err := ServersCollection.FindOne(ctx, filter).Decode(&server)

	if err != nil {
		return server, fmt.Errorf(" GetServerByHostname() no host: %v", err)
	}

	return server, err
}

// GetServerByKey finds a server document by its auth key.
func GetServerByKey(key string) (dbServer, error) {
	filter := bson.M{"key": key}
	server := dbServer{}
	err := ServersCollection.FindOne(ctx, filter).Decode(&server)

	if err != nil {
		return server, fmt.Errorf(" GetServerByKey() no host: %v", err)
	}

	return server, err
}

// insertServer inserts a new server document, rejecting duplicate FQDNs and duplicate keys.
func insertServer(key, fqdn, owner string) (dbServer, error) {

	s := dbServer{}

	s, err := GetServerByHostname(fqdn)

	if err == nil {
		return dbServer{}, errors.New("insertServer: fqdn exists")
	}

	// check for double key
	s, err = GetServerByKey(key)
	if err == nil {
		return dbServer{}, errors.New("insertServer: key exists")
	}

	s.Hostname = fqdn
	s.Key = key
	s.Owner = owner
	s.Active = true
	s.DateInserted = time.Now().Format("02/01/2006 15:04:05")
	_, err = ServersCollection.InsertOne(ctx, s)
	if err != nil {
		return dbServer{}, err
	}

	return s, nil
}

// CreateSessionID derives a YYYYMMDD session ID from a "YYYY-MM-DD HH:MM:SS" date string.
func CreateSessionID(date string) string {
	// date: assume yyyy-mm-dd hh:mm:ss
	return strings.Replace(date[0:10], "-", "", 2)
}

// InsertServerData processes raw server telemetry and stores it in MongoDB.
// If a document for the same (hostname, sessionid) already exists it is replaced (idempotent daily runs).
// Comment and Supressed flags are migrated from the previous session's matching rules by checksum.
// Triggers baseline comparison and, when nmap data is also present for the session, nmap comparison.
func InsertServerData(rawjson RawDataServer) {

	sd := dbServerData{}

	sd.Sdata = ProcessRawServerDataJSON(rawjson)

	s, err := GetServerByKey(sd.Sdata.Key)
	if err != nil {
		log.Println("Server not known, ServerData not Insterted", sd.Sdata.Key)
		return
	}

	serverSessionID := CreateSessionID(sd.Sdata.Date)

	DeleteExistingServerDataIfExists(sd.Sdata.Hostname, sd.Sdata.Key, serverSessionID)
	sd.SessionID = serverSessionID
	sd.Key = sd.Sdata.Key

	insertResult, err := ServerDataCollection.InsertOne(ctx, sd)
	if err != nil {
		log.Println("Failed to insert document: ", err)
		return
	}

	last2, err := GetLast2ServerData(s.Hostname)

	if err != nil {
		log.Println("GetLast2ServerData fail in InsertServerData", err)
	} else {
		for i := range last2[0].Sdata.Fwrules {
			csum1 := createFwruleCsum(last2[0].Sdata.Fwrules[i])
			for j := range last2[1].Sdata.Fwrules {
				csum2 := createFwruleCsum(last2[1].Sdata.Fwrules[j])
				if csum1 == csum2 {
					//copy suppressed and comment
					last2[1].Sdata.Fwrules[j].Comment = last2[0].Sdata.Fwrules[i].Comment
					last2[1].Sdata.Fwrules[j].Supressed = last2[0].Sdata.Fwrules[i].Supressed
				}
			}
		}


		for i := range last2[0].Sdata.Listeners {
			csum1 := createListenerCsum(last2[0].Sdata.Listeners[i])
			for j := range last2[1].Sdata.Listeners {
				csum2 := createListenerCsum(last2[1].Sdata.Listeners[j])
				if csum1 == csum2 {
					//copy suppressed and comment
					last2[1].Sdata.Listeners[j].Comment = last2[0].Sdata.Listeners[i].Comment
					last2[1].Sdata.Listeners[j].Supressed = last2[0].Sdata.Listeners[i].Supressed
				}
			}
		}


		
		// update [0]

		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "sdata", Value: last2[1].Sdata},
			}},
		}

		_, err = ServerDataCollection.UpdateByID(ctx, insertResult.InsertedID, update)
		if err != nil {
			log.Println("Error updating document in InsertServerData:", err)
			return
		}
	}

	//log.Println("Serverdata updated for old comments and Supressed's")

	CompareBaseline(sd.Sdata.Hostname, sd.SessionID)
	if check4ServerAndNmapDocs(sd.Sdata.Key, sd.SessionID) {
		//log.Println("Serverdata Can report on", sd.Sdata.Key, sd.SessionID)
	        CompareFromNMAPViewpoint(sd.Sdata.Hostname, sd.SessionID)
	}

}

// InsertNmapData processes raw nmap results and upserts them into the session's nmapdata document.
// If a NmapHost with the same FromHostname+IPversion+ScannedHostname already exists it is replaced;
// otherwise the new NmapHost is appended. Triggers nmap comparison when server data is also present.
func InsertNmapData(rawjson RawDataNmap) {
	nd := dbNmapData{}

	nd.Ndata = ProcessRawNmapDataJSON(rawjson)

	SessionID := CreateSessionID(nd.Ndata.Date)

	sx, err := GetServerByKey(nd.Ndata.Key)
	if err != nil {
		log.Println("Unknown Key in received NmapData JSON")
		return
	}

	// first get an existing one
	dbnd, err := GetNmapDataByKeyAndSessionID(nd.Ndata.Key, SessionID)
	if err != nil { //new
		//log.Println("New Nmap Session inserted")
		nd.SessionID = SessionID
		nd.Key = nd.Ndata.Key
		_, err := NmapDataCollection.InsertOne(ctx, nd)
		if err != nil {
			log.Println("Failed to insert document:", err)
		}
		if check4ServerAndNmapDocs(nd.Key, nd.SessionID) {
			//log.Println("New Nmap Can report on", nd.Key, nd.SessionID)
	        	CompareFromNMAPViewpoint(sx.Hostname, nd.SessionID)
		}
		return
	}

	//update the Host part
	found := false
	for i, host := range dbnd.Ndata.NmapHosts {
		// test: zit er al een host in de rij? dan replcace
		if host.IPversion == nd.Ndata.NmapHosts[0].IPversion &&
			host.FromHostname == nd.Ndata.NmapHosts[0].FromHostname &&
			host.ScannedHostname == nd.Ndata.NmapHosts[0].ScannedHostname {
			dbnd.Ndata.NmapHosts[i] = nd.Ndata.NmapHosts[0]
			//log.Println("Nmap Session existing updated")
			found = true
			break
		}
	}
	if !found {
		dbnd.Ndata.NmapHosts = append(dbnd.Ndata.NmapHosts, nd.Ndata.NmapHosts[0])
		//log.Println("Nmap Session existing extended")
	}

	// Update
	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "ndata", Value: dbnd.Ndata},
		}},
	}

	_, err = NmapDataCollection.UpdateByID(ctx, dbnd.ID, update)
	if err != nil {
		log.Println("Error updating document in NmapDataCollection:", err)
	}
	if check4ServerAndNmapDocs(dbnd.Key, dbnd.SessionID) {
		//log.Println("Updated Nmap Can report on", dbnd.Key, dbnd.SessionID)
		CompareFromNMAPViewpoint(sx.Hostname, dbnd.SessionID)
	}
}

// check4ServerAndNmapDocs reports whether both a serverdata and an nmapdata document exist for key+sessionid.
func check4ServerAndNmapDocs(key, sessionid string) bool {

	_, err1 := GetServerDataByKeyAndSessionID(key, sessionid)
	_, err2 := GetNmapDataByKeyAndSessionID(key, sessionid)

	//log.Println("check4ServerAndNmapDocs: ", key, sessionid)
	//log.Println("check4ServerAndNmapDocs: ", err1, err2)

	return err1 == nil && err2 == nil
}

// GenPic generates a Mermaid flowchart of the server's interfaces and routes for the Systems tab.
// Each interface gets a button (class IFN) that the UI uses to trigger nmap script generation.
func GenPic(key, sessionid string) string {
	s, err := GetServerDataByKeyAndSessionID(key, sessionid)
	if err != nil {
		log.Println("GenPic: no record found", key, sessionid)
		return ""
	}

	ifmap := make(map[string]int)

	txt := "flowchart TD\n"
	txt += fmt.Sprintf(`subgraph Nmaps["%s"]%c`, s.Sdata.Hostname, '\n')

	for i, iface := range s.Sdata.Interfaces {

		if iface.Name == "lo" {
			continue
		}

		_, ok := ifmap[iface.Name]
		if ok {
			continue
		}

		ifmap[iface.Name] = i

		txt += fmt.Sprintf(`I%d["<button class=IFN id='IFN-%d'>%s</button>`, i, i, iface.Name)
		for _, a := range iface.V4addresses {
			txt += "<br/>" + a
		}
		for _, a := range iface.V6addresses {
			txt += "<br/>" + a
		}
		txt += "\"]\n"

	}
	txt += " end\n"
	txt += fmt.Sprintf(`style Nmaps fill:#BBDEFB%c`, '\n')

	for i, r := range s.Sdata.Routes {
		ms := ""
		m, err := NetmaskToCIDR(r.Mask)
		if err == nil {
			ms = "/" + strconv.Itoa(m)
		}
		txt += fmt.Sprintf(` subgraph N%d["%s%s"]%c`, i, r.Dest, ms, '\n')
		txt += fmt.Sprintf(`  n%d["nmap"]%c`, i, '\n')
		txt += " end\n"
		txt += fmt.Sprintf(`n%d@{ shape: rounded}%c`, i, '\n')
		txt += fmt.Sprintf(`style N%d fill:#BBDEFB%c`, i, '\n')

		ifi := ifmap[r.Interface]
		txt += fmt.Sprintf(`n%d ---> I%d%c`, i, ifi, '\n')
	}

	return txt
}

// CreateNewServer registers a new server with a SHA-256 key derived from FQDN + current epoch.
// Returns the generated key, or an error if the FQDN already exists or is not fully qualified.
func CreateNewServer(newserver, owner string) (string, error) {

	if strings.Count(newserver, ".") < 2 {
		return "", errors.New("error: newserver is not an FQDN")
	}

	// gen Key
	seconds := time.Now().Unix()
	secondsString := strconv.FormatInt(seconds, 10)
	data := newserver + secondsString
	hasher := sha256.New()
	hasher.Write([]byte(data))
	hashBytes := hasher.Sum(nil)
	key := hex.EncodeToString(hashBytes)

	_, err := insertServer(key, newserver, owner)

	if err != nil {
		key = ""
	}
	return key, err
}

// CreateServerCollectorPy generates the Python collector script for servername.
// The script runs ifconfig, netstat, and nft, then POSTs the result to nchecknetserver/api_server.
func CreateServerCollectorPy(servername, nchecknetserver string) (string, error) {

	script := `#!/usr/bin/python3

import json
import os
import platform
import subprocess
import datetime
import os

data = {
	"Listeners": [],
	"Fwrules": [],
	"Interfaces": [],
	"Routes": [],
	"Hostname": "",
	"Date": "",
	"Key": "ABCDEF0123456789"
}

def runp(command):
	result = subprocess.run(
		command,
		capture_output=True,
		text=True,
		check=True
	)
	lines = result.stdout.strip().split("\n")
	return lines

def main():
	data["Hostname"] = platform.node()
	data["Interfaces"] = runp(["/usr/sbin/ifconfig"])
	data["Listeners"] = runp(["/usr/bin/netstat", "-tulpn"])
	data["Routes"] = runp(["/usr/bin/netstat", "-rn"])
	data["Fwrules"] = runp(["/usr/sbin/nft", "list", "ruleset"])

	now = datetime.datetime.now()
	data["Date"] = now.strftime("%Y-%m-%d %H:%M:%S")

	f = open("/var/tmp/nchecknetraw-server.json", "w")
	f.write(json.dumps(data))
	f.close()

	runp(["curl","-k","--data-binary","@/var/tmp/nchecknetraw-server.json","-X","POST","NCHECKNETSERVER/api_server"])
	os.remove("/var/tmp/nchecknetraw-server.json")

main()
`
	s, err := GetServerByHostname(servername)
	if err != nil {
		return "", err
	}

	script = strings.Replace(script, "ABCDEF0123456789", s.Key, 1)
	script = strings.Replace(script, "NCHECKNETSERVER", nchecknetserver, 1)

	return script, nil
}

// CreateNmapCollectorPy generates the Python nmap script for a specific interface on servername.
// iface is an index into Interfaces from the given sessionid. IPv6 scanning is stubbed out in the script.
func CreateNmapCollectorPy(servername, sessionid, iface, nchecknetserver string) (string, error) {

	script := `#!/usr/bin/python3

# Run this script daily from the networks in front of IFACE.

import json
import platform
import subprocess
import datetime
import os

data = {
	"Nmap": [],
	"Hostname": "",
	"Scanname": "",
	"Interfacename": "",
	"Date": "",
	"Key": "ABCDEF0123456789"
}

def runp(command):
	result = subprocess.run(
		command,
		capture_output=True,
		text=True,
		check=True
	)
	lines = result.stdout.strip().split("\n")
	return lines


def scan(scanip):
	global data

	ipv = "4"
	if ":" in scanip:
		return			## tja
		ipv = "6"
		scanip = scanip + "%"+iface

	data["Nmap"] = runp(["/usr/bin/nmap", "-Pn",  "-"+ipv, scanip ])
	data["Hostname"] = platform.node()
	data["Scanname"] = "SCANNAME"
	data["Interfacename"] = "IFACE"
	data["IPv"] = ipv
	now = datetime.datetime.now()
	data["Date"] = now.strftime("%Y-%m-%d %H:%M:%S")

	f = open("/var/tmp/nchecknetraw-nmap.json", "w")
	f.write(json.dumps(data))
	f.close()

	runp(["curl","-k","--data-binary","@/var/tmp/nchecknetraw-nmap.json","-X","POST","NCHECKNETSERVER/api_nmap"])
	os.remove("/var/tmp/nchecknetraw-nmap.json")

def main():
	scanips = SCANIPS
	for s in scanips:
		scan(s)

main()
`
	s, err := GetServerByHostname(servername)
	if err != nil {
		return "", err
	}

	sd, err := GetServerDataByKeyAndSessionID(s.Key, sessionid)
	if err != nil {
		return "", err
	}

	i, _ := strconv.Atoi(iface)

	addresses := ""
	ifa := sd.Sdata.Interfaces[i]

	for _, a := range ifa.V4addresses {
		addresses += `,"` + a + `"`
	}
	for _, a := range ifa.V6addresses {
		addresses += `,"` + a + `"`
	}

	if len(addresses) > 0 {
		addresses = addresses[1:]
	}
	addresses = "[" + addresses + "]"

	script = strings.Replace(script, "ABCDEF0123456789", sd.Key, 1)
	script = strings.Replace(script, "NCHECKNETSERVER", nchecknetserver, 1)
	script = strings.Replace(script, "SCANIPS", addresses, 1)
	script = strings.Replace(script, "SCANNAME", servername, 1)
	script = strings.Replace(script, "IFACE", ifa.Name, 2)

	return script, nil
}

// NoAccess2DB returns true if user does not have permission to access hostname.
// Admins always have access; other users are restricted to servers under their owner.
func NoAccess2DB(user dbUser, hostname string) bool {
	if user.AccessRight == "a" {
		return false
	}

	s, err := GetServerByHostname(hostname)
	if err != nil {
		log.Printf("NoAccess2DB(), no acces for %s to %s: %v \n", user.Name, hostname, err)
		return true
	}

	if s.Owner == user.Owner {
		return false
	}

	log.Println("NoAccess2DB(), bad pair: ", s.Owner, user.Name, s.Hostname)
	return true
}

// CheckPasswordHash reports whether password matches the bcrypt hash.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashPassword returns a bcrypt hash of password using cost 14.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// GetUserByToken finds a user by their stored JWT token.
// JWT tokens are not globally unique but are unique per user, so this lookup is safe.
func GetUserByToken(token string) (dbUser, error) {

	filter := bson.M{"token": token}
	u := dbUser{}
	err := UsersCollection.FindOne(ctx, filter).Decode(&u)
	return u, err
}

// GetUserByName finds a user document by username.
func GetUserByName(name string) (dbUser, error) {
	filter := bson.M{"name": name}
	u := dbUser{}
	err := UsersCollection.FindOne(ctx, filter).Decode(&u)
	return u, err
}

// GetBaseline retrieves the stored baseline session ID for hostname.
func GetBaseline(hostname string) (dbBaseline, error) {
	filter := bson.M{"hostname": hostname}
	b := dbBaseline{}
	err := BaselineCollection.FindOne(ctx, filter).Decode(&b)
	return b, err
}

// DeleteBaseline removes the baseline document for hostname.
func DeleteBaseline(hostname string) {
	filter := bson.M{"hostname": hostname}
	BaselineCollection.DeleteOne(ctx, filter)
}

// SetBaseline upserts the baseline session for hostname (delete-then-insert to replace any existing record).
func SetBaseline(hostname, sessionid string) error {

	_, err := GetServerByHostname(hostname)
        if err != nil {
		return err
	}

	filter := bson.M{"hostname": hostname}
	BaselineCollection.DeleteOne(ctx, filter)

	b := dbBaseline{}
        b.Hostname = hostname
        b.SessionID = sessionid

	_, err = BaselineCollection.InsertOne(ctx, b)
	return err
}

// CreateUser creates a new user with a bcrypt-hashed password, rejecting duplicate usernames.
func CreateUser(name, password, owner, rights string) (dbUser, error) {

	_, err := GetUserByName(name)

	if err == nil {
		return dbUser{}, errors.New("CreateUser: user exists")
	}

	h, err := HashPassword(password)
	if err != nil {
		log.Println("can not hash password")
		return dbUser{}, err
	}

	u := dbUser{}
	u.Name = name
	u.PassHash = h
	u.Active = true
	u.Owner = owner
	u.AccessRight = rights
	u.DateInserted = time.Now().Format("02/01/2006 15:04:05")

	_, err = UsersCollection.InsertOne(ctx, u)
	if err != nil {
		return dbUser{}, err
	}

	return u, nil
}

// UpdateUserToken stores a new JWT token on the user document after a successful login.
// The token is also used by GetUserByToken to authenticate WebSocket requests.
func UpdateUserToken(name, token string) error {
	u, err := GetUserByName(name)
	if err != nil {
		return err
	}

	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "token", Value: token},
		}}}

	_, err = UsersCollection.UpdateByID(ctx, u.ID, update)
	if err != nil {
		log.Println("Error updating Token in document in UsersCollection:", err)
	}
	return err
}

// NetmaskToCIDR converts a 4-octet string netmask to its CIDR integer value.
// Returns an error if the netmask is invalid or not a standard IPv4 mask.
func NetmaskToCIDR(netmaskStr string) (int, error) {
	// Parse the string into a net.IP type
	ip := net.ParseIP(netmaskStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid netmask format: %s", netmaskStr)
	}

	// Convert the 4-octet IP into a 4-byte IPv4 mask type
	ipv4Mask := net.IPMask(ip.To4())
	if ipv4Mask == nil {
		return 0, fmt.Errorf("not a valid IPv4 netmask: %s", netmaskStr)
	}

	// Size returns the number of leading ones and total bits (32 for IPv4)
	ones, bits := ipv4Mask.Size()

	// If the mask is non-contiguous (e.g., 255.0.255.0), Size() returns 0, 0
	if ones == 0 && bits == 0 {
		return 0, fmt.Errorf("non-contiguous or invalid netmask: %s", netmaskStr)
	}

	return ones, nil
}
