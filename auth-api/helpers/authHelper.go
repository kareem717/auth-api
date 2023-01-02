package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// Returns an non-nil error if and only if the user_type of the `user` object from the HTTP request does not match `role`.
func CheckUserType(c *gin.Context, role string) (err error) {
	userType := c.GetString("user_type")
	err = nil
	if userType != role {
		err = errors.New("Unatuheorized to access this resource")
		return err
	}

	return err
}

/* Returns a non-nil error if the user-type of the `user` object from the HTTP request is not "USER" and 
if the `user_id of the object is not the same as the `userId` parameter. Otherwise, returns a non-nill error if
the `user_type` is not the same as the `user_type` in the context.*/
func MatchUserTypeToUID(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("user_id")
	err = nil

	if userType == "USER" && uid != userId {
		err = errors.New("Unauthorized to access this resource")
		return err
	}
	
	err = CheckUserType(c, userType)

	return err 
}
