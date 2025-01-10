package middleware

import (
	helper "github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/helpers"
	"github.com/gin-gonic/gin"
	"net/http"
	"fmt"
	// "errors"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("Authorization")
		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return
		}

		// Log the claims for debugging
		fmt.Printf("Authenticated user: %s, User Type: %s\n", claims.Email, claims.User_type)

		c.Set("email", claims.Email)
		c.Set("first_name", claims.First_name)
		c.Set("last_name", claims.Last_name)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.User_type)
		c.Next()
	}
}