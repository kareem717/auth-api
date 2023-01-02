package main

import (
	"github.com/kareem717/auth-api/routes"
	"os"
	"github.com/gin-gonic/gin"
)

func main() {
	port := os.Getenv("PORT")

	// Setting default port.
	if port == "" {
		port = "8000"
	}

	// Create new router.
	router := gin.New()
	// Log all incoming requests.
	router.Use(gin.Logger())

	// Set up all routes.
	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	// Run server at port `port`
	router.Run(":" + port)
}