package database

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"
    "github.com/joho/godotenv"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func DBinstance() *mongo.Client {
    err := godotenv.Load(".env")
    if err != nil {
        log.Fatal("Error loading .env file:", err)
    }

    MongoDb := os.Getenv("MONGODB_URL")
    if MongoDb == "" {
        log.Fatal("MONGODB_URL is empty")
    }

    serverAPI := options.ServerAPI(options.ServerAPIVersion1)
    opts := options.Client().ApplyURI(MongoDb).SetServerAPIOptions(serverAPI)

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    client, err := mongo.Connect(ctx, opts)
    if err != nil {
        log.Fatal("Error connecting to MongoDB:", err)
    }

    if err := client.Ping(ctx, nil); err != nil {
        log.Fatal("Error pinging MongoDB:", err)
    }

    fmt.Println("Successfully connected to MongoDB!")
    return client
}

func init() {
    Client = DBinstance()
}

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
    var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)
    return collection
}