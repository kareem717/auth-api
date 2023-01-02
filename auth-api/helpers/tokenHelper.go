package helpers

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/kareem717/auth-api/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Represents the claims that are encoded in the JWT token.
type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	UID       string
	UserType  string
	jwt.StandardClaims
}

// Represents the `user`` collection in the MongoDB database.
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var SECRET_KEY string = os.Getenv("SECERET_KEY")

// Generates a new JWT token and a new refresh token and returns them as strings.
func GenerateAllTokens(email, firstName, lastName, userType, userID string) (signedToken, signedRefreshToken string, err error) {
	claims := &SignedDetails {
		Email: email,
		FirstName: firstName,
		LastName: lastName,
		UID: userID,
		UserType: userType,
		StandardClaims: jwt.StandardClaims {
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(2)).Unix(),
		},
	}

	refreshClaims := &SignedDetails {
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(4)).Unix(),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return 
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return 
	}

	return token, refreshToken, err
}

// Updates the token and refresh token for a user with the given `userID``.
func UpdatedAllTokens(signedToken, signedRefreshToken, userID string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100 * time.Second)

	var updateObj primitive.D

	updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
	updateObj = append(updateObj, bson.E{Key: "refreshtoken", Value: signedRefreshToken})

	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{Key: "updatedat", Value: Updated_at})

	upsert := false

	filter := bson.M{"userid":userID}
	opt := options.UpdateOptions {
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj},
		},
		&opt,
	)

	defer cancel()

	if err != nil {
		log.Panic(err)
		return
	}
	return
}

// Validates the provided signed token and returns the claims and any error message.
func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {
	// Parses the token using the secret key and the SignedDetails struct.
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token)(interface{}, error){
			return []byte(SECRET_KEY), nil
		},
	)

	// If there is an error parsing the token, returns the error message.
	if err != nil {
		msg = err.Error()
		return
	}

	// If the claims cannot be converted, returns an error message.
	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		msg = err.Error()
		return
	}

	// If the token has expired, return an error message.
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token is expired.")
	}

	// Returns the claims and an empty string.
	return claims, msg
}
