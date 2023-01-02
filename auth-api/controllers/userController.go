package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/kareem717/auth-api/database"
	"github.com/kareem717/auth-api/helpers"
	"github.com/kareem717/auth-api/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// Creates `userCollection` variable that users `user` collection from MongoDB instance.
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
// Creates a `validator` instance used to validate `User` model.
var validate = validator.New()

// Hashes inputed string with the `bcrypt` algorithm.
func HashPassword(password string) string {
	// Returns the bcrypt hash of the password.
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}

	return string(bytes)
}

// Verifies if `inputPassword` matches the hashed already `providedPassword`.
func VerifyPassword(inputPassword string, hashedPassword string) (bool, string) {
	// Default (if passwords match) return values
	check := true
	msg := ""

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword))
	
	// Error handling for above function.
	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect.")
		check = false
	}

	return check, msg
}

// Handler function for the `/signup` route.
func SignUp() gin.HandlerFunc {
	return func(c *gin.Context){
		// Creates a new context with a timeout of 100 seconds.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		// Initiates the `user` variable which stores the `User` model that is passed with the HTTP request.
		var user models.User
		defer cancel()

		// Parses the `user` variable from the HTTP request and handels possible errors.
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validates that the `user` variable from the HTTP request matches the `validate` tags of the `User` model struct.
		if validationError := validate.Struct(user); validationError != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationError.Error()})
			return
		}

		// Checks if there is an existing document in the `userCollection` with the same `email` as the `user` variable from the HTTP request.
		countEmail, err := userCollection.CountDocuments(ctx, bson.M{"email":user.Email})
		// Releases ctx (context) and the resources it uses as soon as the CountDocuments() function completes.
		defer cancel()
		// Error handling for the above `CountDocuments()` function.
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking user email."})
		}
		if countEmail > 0{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "the email provided is already in use."})
			return 
		}



		// Checks if there is an existing document in the `userCollection` with the same `phone` as the `user` variable from the HTTP request.
		countPhone, err := userCollection.CountDocuments(ctx, bson.M{"phone":user.Phone})
		// Releases ctx (context) and the resources it uses as soon as the CountDocuments() function completes.
		defer cancel()
		// Error handling for the above  `CountDocuments()` function.
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking user phone number."})
		}
		if countPhone > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "the phone number provided is already in use."})
			return 
		}

		// Hashses the given password from the HTTP request and replaces the correlating field in `user`.
		password := HashPassword(*user.Password)
		user.Password = &password

		// Sets the time the `user` is created at in the `CreatedAt` field of the `user` object.
		user.CreatedAt, err = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		// Error handling for above function.
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while getting `created_at` time."})
		}

		// Sets the time the `user` is updated at in the `UpdatedAt` field of the `user` object.
		user.UpdatedAt, err = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		// Error handling for above function.
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while getting `updated_at` time."})
		}

		// Creates a new unique ObjectID, then sets the `ID` field of the `user` object to it.
		user.ID = primitive.NewObjectID()
		// Sets the `user` object's `UserID` field to the hex encoding of the object's `ID` field.
		user.UserID = user.ID.Hex()
		// Uses the `GenerateAllTokens()` function to generate necessary tokens needed for authentication/authorization.
		token, refreshToken, err := helpers.GenerateAllTokens(*user.Email, *user.FirstName, *user.LastName, *user.UserType, *&user.UserID)
		// Error handling for above function.
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating tokens."})
		}

		// Sets the token fields of the `user` object to generated tokens from the `GenerateAllTokens()` function.
		user.Token = &token
		user.RefreshToken = &refreshToken

		// Inserts the `user` object into the `userCollection` and collects the resulting insertion number in `resultInsertionNumber`.
		resultInsertionNumber, insertError := userCollection.InsertOne(ctx, user)
		// Error handling for above function.
		if insertError != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error":msg})
		}

		// Releases ctx (context) and the resources it uses as soon as the InsertOne() function completes.
		defer cancel()
		// Returns a code 200 status and the `resultInsertionNumber`.
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

// Handler function for the `/login` route.
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Creates a new context with a timeout of 100 seconds.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		// Initiates the `user` variable which stores the `User` model that is passed with the HTTP request.
		var user models.User
		// Initiates the `foundUser` variable which will be used to store the `User` model retrived from the `userCollection` that matches the 'email' field of the `User` model passed with the HTTP request.
		var foundUser models.User
		defer cancel()

		// Parses the `user` variable from the HTTP request and handels possible errors.
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}

		// Finds the document in `userCollection` that matches the `user` object's `email` field and stores the decoded verison in `foundUser`.
 		err := userCollection.FindOne(ctx, bson.M{"email":user.Email}).Decode(&foundUser)
		// Releases ctx (context) and the resources it uses as soon as the `FindOne()` function completes.
		defer cancel()
		// Error handling for the above `FindOne()` function, alonside verification that the `foundUser` object is a real/valid user.
		if err != nil || foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error":"email or password is incorrect."})
			return
		}

		// Uses the `VerifyPassword()` function to see if the `user` object's password field matches the same one of the `foundUser` object.
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		// Releases ctx (context) and the resources it uses as soon as the `VerifyPassword()` function completes.
		defer cancel()
		// Error handling for the above `VarifyPassword()` function.
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error":msg})
			return
		}

		// Generates new tokens for the `foundUser` object with use of the `GenerateAllTokens` function.
		token, refreshToken, err := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, *foundUser.UserType, *&foundUser.UserID)
		// Error handling for the above function.
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating tokens."})
			return 
		}

		// Updates all token fields of the `foundUser` email 
		helpers.UpdatedAllTokens(token, refreshToken, foundUser.UserID)

		// Returns a code 200 status and the JSON of `foundUser`.
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context){
		// Uses the `CheckUserType()` to make sure that the autherization token used has a `ADMIN` user type assosiated to it's parent `user` object and handles possible errors. 
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}

		// Creates a new context with a timeout of 100 seconds.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)


		// Paganation
		// Sets the value of the `recordPerPage` query parameter, if it is present.
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			// Default `recordsPerPage` value
			recordPerPage = 10 
		}

		// Sets the value of the `page` query parameter, if it is present.
		page, err := strconv.Atoi(c.Query("page"))
		if err != nil || page < 1 {
			// Default `page` value
			page = 1 
		}

		// Sets the value of the `start index` query parameter, if it is present.
		startIndex, err := strconv.Atoi(c.Query("start index"))
		if err != nil {
			// Default `page` value
			startIndex = (page - 1) *  recordPerPage
		}

		// Gets all documents of the collection.
		matchStage := bson.D{
			{Key: "$match", Value: bson.D{{}}},
		}

		// Groups by `_id` and derives `total_count` of documents of `userCollection`.
		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}}, 
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}}, 
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
			}},
		}

		// Defines that the output should include the `total_count` field, and a `user_items` field, which will contain a slice of bson.M documents that starts from the `startIndex` index and has a length of `recordPerPage` items.
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		// Aggregates the `userCollection` using the above fields.
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})
		// Releases ctx (context) and the resources it uses as soon as the `Aggregate()` function completes.
		defer cancel()
		// Error handling for the `Aggregate()` function.
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error":"error occured whilst listing user items."})
		}
		
		// Initiates final return variable.
		var allUsers []bson.M
		
		// Adds all results of the `Aggregate()` function to `allUsers` and handles possible errors.
		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}

		// Returns a code 200 status and the `allUsers[0]` slice.
		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context){
		// Retrives the `user_id` parameter from URL path.
		userId := c.Param("user_id")
		
		// Makes sure that the type of user that is making the search call is an `ADMIN` if they are looking for a user other than themselves.
		if err := helpers.MatchUserTypeToUID(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}

		// Creates a new context with a timeout of 100 seconds.
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		// Initiates the `user` variable which stores the `User` model of the found.
		var user models.User

		// Finds the user with the matching `userid` as the `userId` parameter and decodes it into the user object.
		err := userCollection.FindOne(ctx, bson.M{"userid":userId}).Decode(&user)
		// Releases ctx (context) and the resources it uses as soon as the `FindOne()` function completes.
		defer cancel()
		// Error handling of the FindOne() funcion.
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Returns a code 200 status and the `users` object.
		c.JSON(http.StatusOK, user)
	}
} 