package routes

import (
	controller "github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/controllers"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.POST("users/signup", controller.Signup())
	incomingRoutes.POST("users/login", controller.Login())
}
