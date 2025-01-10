package routes

import (
	controller "github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/controllers"
	"github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUsers())
}
