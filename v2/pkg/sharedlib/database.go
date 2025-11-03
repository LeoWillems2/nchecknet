package sharedlib

import (
	"context"
	"fmt"
	"log"
	"time"

	_ "go.mongodb.org/mongo-driver/bson" // Essential for defining query filters
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ServerData struct {
	ID     primitive.ObjectID `bson:"_id,omitempty"`
	//Key    string             `bson:"key,omitempty"`
	SessionID  string             `bson:"sessiontime,omitempty"`
	Sdata NcheckNetServer             `bson:"sdata,omitempty"`
}


type NmapData struct {
	ID     primitive.ObjectID `bson:"_id,omitempty"`
	SessionID  string             `bson:"sessiontime,omitempty"`
	Ndata NcheckNetNmap             `bson:"ndata,omitempty"`
}

var ServerDataCollection *mongo.Collection
var NmapDataCollection *mongo.Collection
var ctx = context.Background()

func Test() {
	uri := "mongodb://192.168.100.12:27017"
	clientCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(clientCtx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err = client.Disconnect(clientCtx); err != nil {
			log.Fatalf("Error during disconnection: %v", err)
		}
	}()

	if err = client.Ping(clientCtx, nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	ServerDataCollection = client.Database("nchecknet").Collection("serverdata")
	NmapDataCollection = client.Database("nchecknet").Collection("nmapdata")

	insertServerData()
	insertNmapData()
}


func insertServerData() {
	sd := ServerData{}

	sd.Sdata = ProcessRawServerData("data/nchecknetraw-server.json")
	sd.SessionID = "101020191230"

	insertResult, err := ServerDataCollection.InsertOne(ctx, sd)
	if err != nil {
		log.Fatalf("Failed to insert document: %v", err)
	}
	
	fmt.Println("✅ Document inserted.")
	fmt.Printf("Inserted ID: %v\n", insertResult.InsertedID)
}

func insertNmapData() {
	nd := NmapData{}

	nd.Ndata = ProcessRawNmapData("data/nchecknetraw-nmap.json")
	nd.SessionID = "101020191235"

	insertResult, err := NmapDataCollection.InsertOne(ctx, nd)
	if err != nil {
		log.Fatalf("Failed to insert document: %v", err)
	}
	
	fmt.Println("✅ Document inserted.")
	fmt.Printf("Inserted ID: %v\n", insertResult.InsertedID)
}
