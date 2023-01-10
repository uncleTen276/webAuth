package routes

import (
	"webAuth/controllers"

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	app.Post("/api/register", controllers.Register)
	app.Post("/api/login", controllers.Login)
	app.Get("api/user", controllers.GetUser)
	app.Post("api/logout", controllers.Logout)
}
