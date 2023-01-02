package middleware

import (
	"fmt"
	"net/http"
	"github.com/kareem717/auth-api/helpers"
	"github.com/gin-gonic/gin"
)

// Authenticates an HTTP request by checking the presence and validity of the "token" header.
func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context){
		// Gets the value of the `token`` header.
		clientToken := c.Request.Header.Get("token")

		// Returns an error if the `token`` header is not present, .
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error":fmt.Sprintf("No Authorization Provided.")})
			c.Abort()
			return
		}

		// Validate the token using the `ValidateToken()` function
 		claims, err := helpers.ValidateToken(clientToken)
		// Error handling for the above function.
		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error":err})
			c.Abort()
			return
		}

		// Sets the values of the claims as context values
		c.Set("email", claims.Email)
		c.Set("first_name", claims.FirstName)
		c.Set("last_name", claims.LastName)
		c.Set("user_id", claims.UID)
		c.Set("user_type", claims.UserType)
		c.Next()
	}
}