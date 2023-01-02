package routes

import (
	"github.com/kareem717/auth-api/controllers"
	"github.com/gin-gonic/gin"
)

// Registers all the types of `AuthRoutes`
func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/signup", controllers.SignUp())
	incomingRoutes.POST("users/login", controllers.Login())
}

