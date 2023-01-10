package main

import (
	"webAuth/configs"
	"webAuth/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
	}))
	configs.ConnectDB()
	routes.UserRoute(app)
	app.Listen(":3000")
}
