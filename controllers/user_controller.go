package controllers

import (
	"context"
	// "fmt"
	"net/http"
	"time"
	"webAuth/configs"
	"webAuth/models"
	"webAuth/responses"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "user")
var validate = validator.New()

const SecretKey = "secret"

func Register(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var data map[string]string
	defer cancel()
	if err := c.BodyParser(&data); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{
			Status:  http.StatusBadRequest,
			Message: "error",
			Data:    &fiber.Map{"data": err.Error()}})
	}
	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)
	newUser := models.User{
		Id:       primitive.NewObjectID(),
		Name:     data["name"],
		Email:    data["email"],
		Password: password,
	}

	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{
			Status:  http.StatusInternalServerError,
			Message: "error",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}
	return c.Status(http.StatusCreated).JSON(responses.UserResponse{
		Status:  http.StatusCreated,
		Message: "success",
		Data:    &fiber.Map{"data": result},
	})
}

func Login(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{
			Status:  http.StatusBadRequest,
			Message: "error",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": data["email"]}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(responses.UserResponse{
			Status:  fiber.StatusNotFound,
			Message: "Can't not find email",
			Data:    &fiber.Map{"data": err.Error()},
		})
	}
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{
			Status:  http.StatusBadRequest,
			Message: "incorrect password",
		})
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    user.Id.Hex(),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})

	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(responses.UserResponse{
			Status:  http.StatusBadRequest,
			Message: "Could not login",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.Status(http.StatusCreated).JSON(responses.UserResponse{
		Status:  http.StatusCreated,
		Message: "success",
	})
}

func GetUser(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(responses.UserResponse{
			Status:  fiber.StatusUnauthorized,
			Message: "Unauthenticated",
		})
	}

	claims := token.Claims.(*jwt.StandardClaims)
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	objId, _ := primitive.ObjectIDFromHex(claims.Issuer)
	userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&user)

	return c.JSON(responses.UserResponse{
		Data:    &fiber.Map{"data": user},
		Status:  http.StatusOK,
		Message: "success",
	})
}

func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}
	c.Cookie(&cookie)
	return c.Status(fiber.StatusOK).JSON(responses.UserResponse{
		Status:  fiber.StatusOK,
		Message: "success",
	})
}
