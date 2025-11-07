package sharedlib

import (
	"context"
	//"fmt"
	"log"
	"time"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type dbServer struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Hostname   string             `bson:"hostname,omitempty"`
	Key        string             `bson:"key,omitempty"`
	DateInserted  string          `bson:"dateinserted,omitempty"`
	Active     bool               `bson:"active,omitempty"`
}

type dbServerData struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	SessionID string         `bson:"sessionid,omitempty"`
	Key string         `bson:"key,omitempty"`
	Sdata NcheckNetServer         `bson:"sdata,omitempty"`
}

type dbNmapData struct {
	ID     primitive.ObjectID `bson:"_id,omitempty"`
	SessionID  string             `bson:"sessionid,omitempty"`
	Key  string             `bson:"key,omitempty"`
	Ndata NcheckNetNmap             `bson:"ndata,omitempty"`
}

var ServersCollection *mongo.Collection
var ServerDataCollection *mongo.Collection
var NmapDataCollection *mongo.Collection
var ctx = context.Background()

func DBConnect() (*mongo.Client, error) {
	uri := "mongodb://192.168.100.12:27017"
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

	return client, nil

}

func Test() {
	DBConnect()
	//insertServerData()
	//insertNmapData()
}


func GetNmapDataByKeyAndSessionID(key, sessionid string) (dbNmapData, error) {
        filter := bson.M{"key": key, "sessionid": sessionid}
        nmap := dbNmapData{}
        err := NmapDataCollection.FindOne(ctx, filter).Decode(&nmap)
        return nmap, err
}

func GetServerDataByKeyAndSessionID(key, sessionid string) (dbServerData, error) {
        filter := bson.M{"key": key, "sessionid": sessionid}
        server := dbServerData{}
        err := ServerDataCollection.FindOne(ctx, filter).Decode(&server)
        return server, err
}


func DeleteExistingServerDataIfExists(hostname, key, sessionid string){
        filter := bson.M{"sdata.hostname": hostname, "sdata.key": key, "sessionid": sessionid}
	// feitelijk hoeft de lookup niet.

        serverdata := dbServerData{}
        err := ServerDataCollection.FindOne(ctx, filter).Decode(&serverdata)

	if err == nil {
        	ServerDataCollection.DeleteOne(ctx, filter)
		log.Println("Serverdata deleted")
	}
}
func GetServerByHostname(hostname string) (dbServer, error) {
        filter := bson.M{"hostname": hostname}
        server := dbServer{}
        err := ServersCollection.FindOne(ctx, filter).Decode(&server)
        return server, err
}
func GetServerByKey(key string) (dbServer, error) {
        filter := bson.M{"key": key}
        server := dbServer{}
        err := ServersCollection.FindOne(ctx, filter).Decode(&server)
        return server, err
}

// insertServer inserts a new Server if it does not already exist. It also checks for double Keys.
func insertServer(sdata NcheckNetServer) dbServer {

	s := dbServer{}

	s, err := GetServerByHostname(sdata.Hostname)

	if err == nil {
		//log.Println("Insert Server: exists")
		return s
	}

	// check for double key
	s, err = GetServerByKey(sdata.Key)
	if err == nil {
		log.Fatalln("Insert Server: Key e1 already in use, not inserted", s)
		return dbServer{}
	}

	s.Hostname = sdata.Hostname
	s.Key = sdata.Key
	s.Active = true
	s.DateInserted = time.Now().Format("02/01/2006 15:04:05")
	_, err = ServersCollection.InsertOne(ctx, s)
	if err != nil {
		log.Fatalln("Failed to insert document: %v\n", err)
		return dbServer{}
	}

	return s
}

func CreateSessionID(date string) string {
	// date: assume yyyy-mm-dd hh:mm:ss
	return strings.Replace(date[0:10], "-", "", 2)
}

/*
InsertServerData first inserts a Server document if the Server is unknown.
After that, the ServerData is inserted but it replaces a earlier document if the
SessionID has te same (day) range.
After thasd.Sdata.Datet, the NmapData is inserted in a document that already has the same SessionID (if not exists, it is added) but records with matching source-host+ipversion are replaced,
otherwise they are added.
*/
func InsertServerData(rawjson RawDataServer) {

	sd := dbServerData{}

	sd.Sdata = ProcessRawServerDataJSON(rawjson)

	serverSessionID := CreateSessionID(sd.Sdata.Date)

	insertServer(sd.Sdata)

	DeleteExistingServerDataIfExists(sd.Sdata.Hostname, sd.Sdata.Key, serverSessionID)

	sd.SessionID = serverSessionID
	sd.Key = sd.Sdata.Key

	_, err := ServerDataCollection.InsertOne(ctx, sd)
	if err != nil {
		log.Fatalf("Failed to insert document: %v", err)
	}

	log.Println("Serverdata inserted")

	if check4ServerAndNmapDocs(sd.Sdata.Key,sd.SessionID) {
		log.Println("Serverdata Can report on", sd.Sdata.Key,sd.SessionID)
	}
	
	//fmt.Printf("Inserted ID: %v\n", insertResult.InsertedID)
}

func InsertNmapData(rawjson RawDataNmap) {
	nd := dbNmapData{}

	nd.Ndata = ProcessRawNmapDataJSON(rawjson)

	SessionID := CreateSessionID(nd.Ndata.Date)

	_, err := GetServerByKey(nd.Ndata.Key)
	if err != nil {
		log.Println("Unknown Key in received NmapData JSON")
		return
	}


	// first get an existing one
	dbnd, err := GetNmapDataByKeyAndSessionID(nd.Ndata.Key, SessionID)
	if err != nil { //new
		log.Println("New Nmap Session inserted")
		nd.SessionID = SessionID
		nd.Key = nd.Ndata.Key
		_, err := NmapDataCollection.InsertOne(ctx, nd)
		if err != nil {
			log.Fatalf("Failed to insert document: %v", err)
		}
		if check4ServerAndNmapDocs(nd.Key,nd.SessionID) {
			log.Println("New Nmap Can report on", nd.Key,nd.SessionID)
		}
		return;
	}

	//update the Host part
	found := false
	for i, host := range dbnd.Ndata.NmapHosts {
		// test: zit er al een host in de rij? dan replcace
		if host.IPversion == nd.Ndata.NmapHosts[0].IPversion &&
		   host.FromHostname == nd.Ndata.NmapHosts[0].FromHostname   &&
		   host.ScannedHostname == nd.Ndata.NmapHosts[0].ScannedHostname {
			dbnd.Ndata.NmapHosts[i] = nd.Ndata.NmapHosts[0]
			log.Println("Nmap Session existing updated")
			found = true
			break
		}
	}
	if !found {
		dbnd.Ndata.NmapHosts = append(dbnd.Ndata.NmapHosts,nd.Ndata.NmapHosts[0] )
		log.Println("Nmap Session existing extended")
	}

	// Update
	update := bson.D{
		{"$set", bson.D{
			{"ndata", dbnd.Ndata},
		}},
	}

	_, err = NmapDataCollection.UpdateByID(ctx, dbnd.ID, update)
	if err != nil {
		log.Fatal("Error updating document in NmapDataCollection:", err)
	}
	if check4ServerAndNmapDocs(dbnd.Key,dbnd.SessionID) {
		log.Println("Updated Nmap Can report on", dbnd.Key,dbnd.SessionID)
	}
}

func check4ServerAndNmapDocs(key,sessionid string) bool {

	_, err1 := GetServerDataByKeyAndSessionID(key, sessionid)
	_, err2 := GetNmapDataByKeyAndSessionID(key, sessionid)

	//log.Println("check4ServerAndNmapDocs: ", key, sessionid)
	//log.Println("check4ServerAndNmapDocs: ", err1, err2)

	return err1 == nil && err2 == nil
}
