package controllers

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "time"
    "github.com/gin-gonic/gin"
    "github.com/go-playground/validator"
    helper "github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/helpers"
    "github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/models"
    "github.com/Aadityaa2004/Go-Lang-Authentication_and_Authorization/database"
    "golang.org/x/crypto/bcrypt"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(hash)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		check = false
		msg = fmt.Sprintf("Invalid password")
	}
	return check, msg
}


func Signup() gin.HandlerFunc {
    return func(c *gin.Context) {
        var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        defer cancel()
        var user models.User

        // Bind JSON to user struct
        if err := c.BindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // Validate the struct
        validationErr := validate.Struct(user)
        if validationErr != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
            return
        }

        // Check if email exists
        count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking email"})
            return
        }

        // Check if phone exists
        phoneCount, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking phone"})
            return
        }

        if count > 0 || phoneCount > 0 {
            c.JSON(http.StatusConflict, gin.H{"error": "Email or Phone Number already exists"})
            return
        }

        // Hash password
        if user.Password != nil {
            hashedPassword := HashPassword(*user.Password)
            user.Password = &hashedPassword
        }

        // Set timestamps
        now := time.Now()
        user.Created_at = now
        user.Updated_at = now

        // Generate new ObjectID and set User_id
        user.ID = primitive.NewObjectID()
        userId := user.ID.Hex()
        user.User_id = &userId

        // Generate tokens
        if user.Email != nil && user.First_name != nil && user.Last_name != nil && user.User_type != nil && user.User_id != nil {
            token, refreshToken, err := helper.GenerateAllTokens(
                *user.Email,
                *user.First_name,
                *user.Last_name,
                *user.User_type,
                *user.User_id,
            )
            if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating tokens"})
                return
            }
            user.Token = &token
            user.RefreshToken = &refreshToken
        }

        // Insert user into database
        result, err := userCollection.InsertOne(ctx, user)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
            return
        }

        // Return success response
        c.JSON(http.StatusCreated, gin.H{
            "message": "User created successfully",
            "userId": user.User_id,
            "insertedId": result.InsertedID,
        })
    }
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check email
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Email not found"})
			return
		}

		// Check password
		if foundUser.Password == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found or password is nil"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password) 
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, *foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, *foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": *foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, foundUser)
	}
}


func GetUsers() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Check if user is admin
        if err := helper.CheckUserType(c, "ADMIN"); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // Log the request for debugging
        fmt.Println("Admin user accessing /users endpoint")

        var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        defer cancel()

        // Handle recordPerPage parameter
        recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
        if err != nil || recordPerPage < 1 {
            recordPerPage = 10
        }

        // Handle page parameter
        page, err := strconv.Atoi(c.Query("page"))
        if err != nil || page < 1 {
            page = 1
        }

        // Calculate startIndex
        startIndex := (page - 1) * recordPerPage

        // Create MongoDB pipeline stages
        matchStage := bson.D{{"$match", bson.D{{}}}}
        groupStage := bson.D{{
            "$group", bson.D{
                {"_id", nil},
                {"total_count", bson.D{{"$sum", 1}}},
                {"data", bson.D{{"$push", "$$ROOT"}}},
            },
        }}
        projectStage := bson.D{{
            "$project", bson.D{
                {"_id", 0},
                {"total_count", 1},
                {"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
            },
        }}

        // Execute aggregation pipeline
        result, err := userCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage, projectStage})
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while listing user items"})
            return
        }

        // Decode the results
        var allUsers []bson.M
        if err = result.All(ctx, &allUsers); err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while decoding user data"})
            return
        }

        c.JSON(http.StatusOK, allUsers)
    }
}
	

func GetUser() gin.HandlerFunc {
    return func(c *gin.Context) {
        userId := c.Param("user_id")
        if err := helper.MatcherUserTypeToUid(c, userId); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        defer cancel()
        var user models.User
        err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        c.JSON(http.StatusOK, user)
    }
}