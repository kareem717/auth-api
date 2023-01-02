package routes

import (
	"github.com/kareem717/auth-api/controllers"
	"github.com/kareem717/auth-api/middleware"
	"github.com/gin-gonic/gin"
)

// Registers all the types of `AuthRoutes`
func UserRoutes(incomingRoutes *gin.Engine){
	// Uses the `Authenticate()` middleware on all routes to check for a valid JWT token in the request header.
	incomingRoutes.Use(middleware.Authenticate())
	
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
}

