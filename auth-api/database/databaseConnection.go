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

// Creates and connects to a MongoDB instance.
func DBInstance() *mongo.Client {
	if err := godotenv.Load(".env"); err != nil {
	log.Fatal("Error while loading the `.env` file.")
	}

	// Gets the MongoDB URL from the .env file.
	MongoDB := os.Getenv("MONGODB_URL")

	// Creates a new MongoDB client
	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDB))
	if err != nil {
		log.Fatal(err)
	}

	// Creates a context with a timeout of 10 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to the MongoDB instance.
	if err = client.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	return client
} 

// Global variable that holds a MongoDB client instance.
var Client *mongo.Client = DBInstance()

// Returns a pointer to a MongoDB collection.
func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	// Stores reference to the specified collection.
	var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)
	return collection
}